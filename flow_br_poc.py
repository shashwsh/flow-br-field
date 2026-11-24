#!/usr/bin/env python3
#
# Flow SMSP backup/restore (script-based). See README.md for the procedure.
#
#   backup      : SMSP IDF + SMSP ZK -> tar.gz streamed over ssh to the backup host
#   restore     : tar.gz -> SMSP ZK (allow-listed nodes) -> SMSP IDF -> replay
#                 (SMSP migration recovery reprograms ANC/PolicyDB)
#   force-retire: after the SMSP is lost, clear its orphaned Flow Controller on PC
#
# Run on a PCVM with the Atlas venv (/home/nutanix/.venvs/bin/bin/python3); the
# SMSP is discovered and reached over the iKat tunnel. Inside the SMSP atlas
# pod, pass --idf-ip idf --zk-host-port zk-cs:9876 instead.

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid
import zlib

import gflags

from insights_interface import insights_interface_pb2
from insights_interface.insights_interface import InsightsInterface
from insights_interface.cpdb_interface import cpdb_utils
from insights_interface.cpdb_interface.cpdb import Cpdb
from insights_interface.cpdb_interface.cpdb_query import (
    COL, EXISTS, NOT, OR, QUERY)

FLAGS = gflags.FLAGS
MANIFEST_NAME = "backup_manifest.json"
DEFAULT_IDF_PORT = 2027
GET_ENTITIES_BATCH = 500

# Mirrors atlas SMSP_MIGRATION_ENTITY_TYPES_LIST (atlas/flow_smsp/consts.py).
# Kept in sync by hand with flow_br_baseline.py.
SMSP_ENTITY_TYPES = [
    "atlas_cidr", "atlas_cloud_config", "atlas_cloud_network",
    "atlas_cloud_provisioning_params", "atlas_cluster_health",
    "atlas_controller_migration_config", "atlas_external_routing_domain",
    "atlas_floating_ip", "atlas_flow_gateway", "atlas_load_balancer_session",
    "atlas_load_balancer_session_target",
    "atlas_map_virtual_network_external_subnet", "atlas_migration_config",
    "atlas_network_function", "atlas_nic_profile", "atlas_port",
    "atlas_port_set", "atlas_port_set_address_set_map", "atlas_route_table",
    "atlas_routing_policy", "atlas_security_group", "atlas_subnet",
    "atlas_virtual_network", "bgp_session", "distributed_virtual_switch",
    "distributed_virtual_switch_breakfix", "filter", "flex_security_group",
    "flow_abac_entity_capability", "flow_migration_config", "host_nic",
    "id_categorization_mapping", "ipfix_exporter", "layer2_stretch",
    "network_address_group", "network_entity_group", "network_function_chain",
    "network_function_chain2", "network_security_policies_export",
    "network_security_policy", "network_security_rule_info",
    "network_security_sync_job", "network_service_group", "port_set",
    "qos_profile", "qos_profile_association", "route", "security_group",
    "span_session", "span_session_stats", "virtual_network", "vpn_connection",
    "vpn_gateway",
]

# Replay mints fresh uuids for these, so restored rows would only be orphans.
# They are backed up (for diffing) and flushed on restore, never re-attached.
# Port set uuids are uuid5(<ZK scope uuid>, <category>) and the scope uuids are
# not restored, so replay re-creates port sets (and their randomly named
# generated address sets) under the rebuilt SMSP's own namespace.
REPLAY_MINTED_TABLES = [
    "atlas_port_set",
    "atlas_port_set_address_set_map",
    "atlas_security_group",
    "flex_security_group",
    "security_group",
]

DEFAULT_SMSP_ZK_PORT = 9876
ZK_JSON_NAME = "smsp_zk_nodes.json"
IKAT_TUNNEL_PC_ENDPOINT = "smsp-%s.ntnx-ikat.svc"
MSPCTL = "/usr/local/nutanix/cluster/bin/mspctl"
DEFAULT_BACKUP_ROOT = "/home/nutanix/flow_br_backups"
DEFAULT_SCP_PATH = "~/flow_backups"
DEFAULT_SSH_KEY = "/home/nutanix/.ssh/flow_br_backup"
DEFAULT_KNOWN_HOSTS = "/home/nutanix/flow_br/known_hosts"
PC_IKAT_NAMESPACE = "ntnx-ikat"
SMSP_IKAT_CONFIGMAP = "ikat-control-plane-config"
SMSP_IKAT_DAEMONSET = "ikat"
PC_NODE_PROXY_DAEMONSET = "node-proxy-daemonset"
IDF_IKAT_PORT = 2027
IDF_IKAT_TARGET_PORT = 9359
IDF_IKAT_CONNECT_TIMEOUT = 120

# Appended to the live iKat control-plane configuration when a replacement
# SMSP's chart lacks this route. Helm owns the source chart; this is a
# deliberately temporary live reconciliation until the chart is updated.
IDF_IKAT_SERVICE_SET = """\
        - service_watcher:
            type: "static"
            config:
              services:
              - name: idf
                port: 2027
                is_tcp: true
                headers_match: {"original_dst_port": "2027"}
          endpoint_watcher:
            type: "static"
            config:
              clusters:
              - cluster_fqdn: "idf.ntnx-flow"
            common_cluster_config: *common_dns_config
"""

# Snapshotted wholesale; only ZK_RESTORE_PATHS is ever written back.
ZK_BACKUP_ROOTS = [
    "/appliance/logical/flow",
    "/appliance/logical/microseg",
    "/appliance/logical/atlas",
    "/appliance/logical/flow_smsp",
]

# Kratos identifies its default quarantine policies only by these uuids. Left at
# the rebuilt SMSP's values, they point at policies the IDF flush removed, and
# Kratos re-creates them next to the restored ones. Everything else under the
# roots (scope uuids, atlas_config, leader election, migration state) is kept
# as the rebuilt SMSP wrote it.
ZK_RESTORE_PATHS = [
    "/appliance/logical/flow/default_policies/strict_quarantine_policy_uuid",
    "/appliance/logical/flow/default_policies/forensic_quarantine_policy_uuid",
]


def init_gflags():
  """Mark gflags parsed with defaults; Nutanix libs fail on unparsed flags."""
  FLAGS(sys.argv[:1])


def connect_cpdb(idf_ip, idf_port):
  client = InsightsInterface(idf_ip, idf_port)
  return Cpdb(client)


def discover_smsp_uuid():
  """UUID of the Flow SMSP registered with this PC, via mspctl."""
  try:
    out = subprocess.check_output([MSPCTL, "cluster", "list", "-o", "json"])
  except (OSError, subprocess.CalledProcessError) as ex:
    raise SystemExit("cannot list MSP clusters with %s (%s); run on a PCVM or "
                     "pass --smsp-uuid" % (MSPCTL, ex))
  smsps = [c for c in json.loads(out)
           if c.get("cluster_type") == "service_msp"]
  flow = [c for c in smsps if c.get("cluster_name") == "flow"] or smsps
  if len(flow) != 1:
    raise SystemExit("expected exactly one Flow SMSP, found %d (%s); pass "
                     "--smsp-uuid" % (len(flow), ", ".join(
                         c.get("cluster_uuid", "?") for c in flow) or "none"))
  return flow[0]["cluster_uuid"]


def resolve_smsp_endpoints(args):
  """Fill in the SMSP IDF ip from the iKat tunnel unless --idf-ip was given.

  The IDF client needs an IP, so the tunnel name is resolved here. The SMSP
  uuid is kept on args so ZK goes through the same tunnel.
  """
  if args.idf_ip:
    return
  if not args.smsp_uuid:
    args.smsp_uuid = discover_smsp_uuid()
  tunnel = IKAT_TUNNEL_PC_ENDPOINT % args.smsp_uuid
  try:
    args.idf_ip = socket.gethostbyname(tunnel)
  except socket.gaierror as ex:
    raise SystemExit("cannot resolve %s (%s); is the SMSP registered with "
                     "this PC?" % (tunnel, ex))
  print("[smsp] %s -> IDF %s:%d, ZK %s"
        % (args.smsp_uuid, args.idf_ip, args.idf_port,
           resolve_zk_endpoint(args)))


# Facade + Ensure Desired State: hide the two-cluster iKat reconciliation
# behind the backup/restore preflight so a caller needs no chart-specific
# knowledge.
def has_idf_ikat_service_set(control_plane_yaml):
  """Whether SMSP iKat has the static TCP ingress route for IDF."""
  return ("- name: idf" in control_plane_yaml and
          "port: %d" % IDF_IKAT_PORT in control_plane_yaml and
          'headers_match: {"original_dst_port": "%d"}' % IDF_IKAT_PORT
          in control_plane_yaml and
          "- cluster_fqdn: \"idf.ntnx-flow\"" in control_plane_yaml)


def ensure_idf_ikat_service_set(control_plane_yaml):
  """Return (updated_yaml, changed) with the IDF ingress route present."""
  if has_idf_ikat_service_set(control_plane_yaml):
    return control_plane_yaml, False
  if ("tcp_ingress_watcher_configs:" not in control_plane_yaml or
      "service_sets:" not in control_plane_yaml or
      not control_plane_yaml.rstrip().endswith(
          "common_cluster_config: *common_dns_config")):
    raise RuntimeError("SMSP iKat ConfigMap does not match the expected "
                       "static service_sets layout")
  return control_plane_yaml.rstrip() + "\n" + IDF_IKAT_SERVICE_SET, True


def has_idf_ikat_service_port(service):
  """Whether the PC iKat Service exposes IDF through node-proxy."""
  return any(port.get("port") == IDF_IKAT_PORT and
             port.get("targetPort") == IDF_IKAT_TARGET_PORT
             for port in service.get("spec", {}).get("ports", []))


def pc_ikat_kubectl(*cmd):
  """Run an explicit PC-side iKat kubectl command without shell interpolation."""
  try:
    return subprocess.check_output(
        ["sudo", "-n", "kubectl", "-n", PC_IKAT_NAMESPACE] + list(cmd),
        stderr=subprocess.STDOUT).decode("utf-8")
  except (OSError, subprocess.CalledProcessError) as ex:
    output = (ex.output.decode("utf-8", "replace")
              if isinstance(ex, subprocess.CalledProcessError) and ex.output
              else str(ex))
    raise SystemExit("[ikat] PC kubectl failed: %s" % output.strip())


def wait_for_idf_ikat_tunnel(smsp_uuid, timeout=IDF_IKAT_CONNECT_TIMEOUT):
  """Fail closed until the PC can reach SMSP IDF through the repaired route."""
  host = IKAT_TUNNEL_PC_ENDPOINT % smsp_uuid
  deadline = time.time() + timeout
  last_error = None
  while time.time() < deadline:
    try:
      with socket.create_connection((host, IDF_IKAT_PORT), timeout=5):
        print("[ikat] PC -> %s:%d reachable" % (host, IDF_IKAT_PORT))
        return
    except (OSError, socket.gaierror) as ex:
      last_error = ex
      time.sleep(2)
  raise SystemExit("[ikat] PC cannot reach %s:%d after %ds (%s)" %
                   (host, IDF_IKAT_PORT, timeout, last_error))


def ensure_idf_ikat(args):
  """Reconcile PC -> SMSP IDF iKat routing before backup or restore.

  Each side is patched and restarted only when its route is missing, so a
  configured setup costs two reads and a connect. Runs before endpoint
  resolution, including for ``restore --dry-run``: the dry-run does not write
  ZK/IDF/policy state, but the PC must first have a usable IDF route to
  inspect that state.
  """
  if args.idf_ip:
    print("[ikat] skipped: explicit --idf-ip=%s" % args.idf_ip)
    return
  if not args.smsp_uuid:
    args.smsp_uuid = discover_smsp_uuid()

  # SMSP iKat ConfigMap/DaemonSet live in ntnx-ikat, not ntnx-flow.
  with smsp_kubectl(PC_IKAT_NAMESPACE) as kubectl:
    configmap = json.loads(kubectl(
        "get", "configmap", SMSP_IKAT_CONFIGMAP, "-o", "json"))
    try:
      control_plane_yaml = configmap["data"]["ikat_control_plane_yaml"]
    except KeyError:
      raise SystemExit("[ikat] %s has no data.ikat_control_plane_yaml" %
                       SMSP_IKAT_CONFIGMAP)
    updated_yaml, changed = ensure_idf_ikat_service_set(control_plane_yaml)
    if changed:
      kubectl("patch", "configmap", SMSP_IKAT_CONFIGMAP, "--type", "merge",
              "-p", json.dumps({"data": {
                  "ikat_control_plane_yaml": updated_yaml}}))
      print("[ikat] added SMSP IDF ingress route idf.ntnx-flow:%d" %
            IDF_IKAT_PORT)
      kubectl("rollout", "restart", "daemonset/%s" % SMSP_IKAT_DAEMONSET)
      kubectl("rollout", "status", "daemonset/%s" % SMSP_IKAT_DAEMONSET,
              "--timeout=180s")
    else:
      print("[ikat] SMSP IDF ingress route already present")

  service_name = "smsp-%s" % args.smsp_uuid
  service = json.loads(pc_ikat_kubectl(
      "get", "service", service_name, "-o", "json"))
  conflicting_port = next(
      (port for port in service.get("spec", {}).get("ports", [])
       if port.get("port") == IDF_IKAT_PORT),
      None)
  if conflicting_port and not has_idf_ikat_service_port(service):
    raise SystemExit("[ikat] PC Service %s already exposes %d with "
                     "targetPort=%r, expected %d" %
                     (service_name, IDF_IKAT_PORT,
                      conflicting_port.get("targetPort"),
                      IDF_IKAT_TARGET_PORT))
  if not has_idf_ikat_service_port(service):
    pc_ikat_kubectl(
        "patch", "service", service_name, "--type=json", "-p",
        json.dumps([{"op": "add", "path": "/spec/ports/-",
                     "value": {"name": "idf", "port": IDF_IKAT_PORT,
                               "protocol": "TCP",
                               "targetPort": IDF_IKAT_TARGET_PORT}}]))
    print("[ikat] added PC Service port %d -> %d" %
          (IDF_IKAT_PORT, IDF_IKAT_TARGET_PORT))
    pc_ikat_kubectl(
        "rollout", "restart", "daemonset/%s" % PC_NODE_PROXY_DAEMONSET)
    pc_ikat_kubectl(
        "rollout", "status", "daemonset/%s" % PC_NODE_PROXY_DAEMONSET,
        "--timeout=180s")
  else:
    print("[ikat] PC Service port %d already present" % IDF_IKAT_PORT)
  wait_for_idf_ikat_tunnel(args.smsp_uuid)


def resolve_zk_endpoint(args):
  """SMSP ZK host:port from the CLI, or None.

  Never defaults to a local session: on a PCVM that would be PC's own ZK, which
  holds the same paths with different values.
  """
  if args.zk_host_port:
    return args.zk_host_port
  if args.smsp_uuid:
    return "%s:%d" % (IKAT_TUNNEL_PC_ENDPOINT % args.smsp_uuid,
                      DEFAULT_SMSP_ZK_PORT)
  return None


def connect_zk(host_port, timeout=120):
  from zeus.zookeeper_session import ZookeeperSession
  session = ZookeeperSession(host_port_list=host_port)
  if not session.wait_for_connection(timeout=timeout):
    raise RuntimeError("failed to connect to Zookeeper at %s" % host_port)
  return session


def zk_bytes(value):
  if value is None:
    return None
  if isinstance(value, str):
    return value.encode("utf-8")
  return bytes(value)


def zk_display(value):
  if value is None:
    return "<absent>"
  if not value:
    return "<empty>"
  return value.decode("utf-8", "replace")


def zk_dump_tree(zk, path, out):
  """Snapshot the subtree at <path> into {path -> {b64, text}}.

  Some values are serialized protos, so b64 is authoritative; text is only for
  human inspection.
  """
  value = zk.get(path)
  if value is None:
    return out
  raw = zk_bytes(value)
  try:
    text = raw.decode("utf-8")
  except UnicodeDecodeError:
    text = None
  out[path] = {"b64": base64.b64encode(raw).decode("ascii"), "text": text}
  for child in (zk.list(path) or []):
    zk_dump_tree(zk, "%s/%s" % (path.rstrip("/"), child), out)
  return out


def create_parent_zk_paths(zk, path):
  """mkdir -p for <path>'s ancestors only; creating the leaf here would make
  the caller's create() fail with "node exists"."""
  parts = path.strip("/").split("/")
  for idx in range(1, len(parts)):
    ancestor = "/" + "/".join(parts[:idx])
    if zk.create(ancestor, b"") is None and zk.error() != "node exists":
      raise RuntimeError("failed to create ZK path %s: %s"
                         % (ancestor, zk.error()))


def zk_set(zk, path, value):
  """Set <path> to <value>, creating it and its ancestors if absent.

  The fresh SMSP has already minted these nodes, so this must overwrite. A node
  can also exist with no value, which get() reports as absent; hence the
  create-then-set fallback.
  """
  if zk.get(path) is not None:
    if not zk.set(path, value):
      raise RuntimeError("failed to set ZK node %s: %s" % (path, zk.error()))
    return "overwritten"
  create_parent_zk_paths(zk, path)
  if not zk.create(path, value):
    if zk.error() != "node exists":
      raise RuntimeError("failed to create ZK node %s: %s" % (path, zk.error()))
    if not zk.set(path, value):
      raise RuntimeError("failed to set existing empty ZK node %s: %s"
                         % (path, zk.error()))
    return "set (node existed empty)"
  return "created"


# --------------------------------------------------------------------------- #
# Backup status in PC ZK (read by PC Atlas to raise backup alerts)
# --------------------------------------------------------------------------- #
# Contract with atlas/flow_smsp/field_br.py; keep field names in sync.
FIELD_BR_ZK_PATH = "/appliance/logical/flow_smsp/field_br"
FIELD_BR_TIMER_ZK_DIR = FIELD_BR_ZK_PATH + "/timer"
FIELD_BR_STATUS_VERSION = 1
SCRIPT_VERSION = "1.1"

ERR_BACKUP_FAILED = "BACKUP_FAILED"
ERR_REMOTE_UNREACHABLE = "REMOTE_UNREACHABLE"
ERR_REMOTE_AUTH_FAILED = "REMOTE_AUTH_FAILED"
ERR_REMOTE_HOSTKEY_MISMATCH = "REMOTE_HOSTKEY_MISMATCH"
ERR_REMOTE_WRITE_FAILED = "REMOTE_WRITE_FAILED"
ERR_SMSP_IDF_UNREACHABLE = "SMSP_IDF_UNREACHABLE"
ERR_SMSP_ZK_UNREACHABLE = "SMSP_ZK_UNREACHABLE"
ERR_CONFIG_INVALID = "CONFIG_INVALID"
TRANSIENT_ERROR_CODES = frozenset([
    ERR_BACKUP_FAILED, ERR_REMOTE_UNREACHABLE, ERR_SMSP_IDF_UNREACHABLE,
    ERR_SMSP_ZK_UNREACHABLE])

RETRY_DELAYS_SECS = (10, 30, 60)
SMSP_RETRY_DELAYS_SECS = (30, 30, 30)
MAX_ERROR_LEN = 300

SSH_STDERR_CODES = [
    (re.compile(r"Host key verification failed|REMOTE HOST IDENTIFICATION "
                r"HAS CHANGED|No .* host key is known"),
     ERR_REMOTE_HOSTKEY_MISMATCH),
    (re.compile(r"Permission denied|Too many authentication failures"),
     ERR_REMOTE_AUTH_FAILED),
    (re.compile(r"No space left|Disk quota exceeded|Read-only file system|"
                r"cannot create directory|Not a directory"),
     ERR_REMOTE_WRITE_FAILED),
    (re.compile(r"Connection timed out|Connection refused|No route to host|"
                r"Network is unreachable|Could not resolve hostname|"
                r"Connection reset|Connection closed|Broken pipe|"
                r"Operation timed out|timed out"),
     ERR_REMOTE_UNREACHABLE),
]


class BackupError(Exception):
  """Backup failure with an error code recorded in the PC ZK status."""

  def __init__(self, code, message):
    super(BackupError, self).__init__(message)
    self.code = code


def now_usecs():
  return int(time.time() * 1e6)


def format_usecs_utc(usecs):
  """Human UTC timestamp for display; ZK keeps raw usecs for Atlas."""
  if not usecs:
    return "never"
  try:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC",
                         time.gmtime(int(usecs) / 1e6))
  except (OverflowError, OSError, ValueError):
    return "invalid(%s)" % usecs


def with_human_times(obj):
  """Return a copy of dict/list with *_utc next to every *_usecs field."""
  if isinstance(obj, dict):
    out = {}
    for key, value in obj.items():
      out[key] = with_human_times(value)
      if key.endswith("_usecs"):
        out[key[:-6] + "_utc"] = format_usecs_utc(value)
    return out
  if isinstance(obj, list):
    return [with_human_times(item) for item in obj]
  return obj


def short_error(message):
  message = " ".join(str(message).split())
  return message[:MAX_ERROR_LEN]


def classify_ssh_failure(returncode, stderr):
  """Error code for a failed ssh/scp to the backup host.

  ssh exits 255 for its own failures; any other non-zero exit is the remote
  command failing, i.e. the backup directory could not be written.
  """
  for pattern, code in SSH_STDERR_CODES:
    if pattern.search(stderr or ""):
      return code
  return ERR_REMOTE_UNREACHABLE if returncode == 255 else ERR_REMOTE_WRITE_FAILED


def with_retries(fn, delays, what):
  """Run fn(), retrying transient BackupErrors after each delay in <delays>."""
  for attempt, delay in enumerate(list(delays) + [None]):
    try:
      return fn()
    except BackupError as ex:
      if ex.code not in TRANSIENT_ERROR_CODES or delay is None:
        raise
      print("[backup] %s failed (%s: %s); retry %d/%d in %ds"
            % (what, ex.code, short_error(ex), attempt + 1, len(delays), delay))
      time.sleep(delay)


def connect_pc_zk(timeout=30):
  """Session to this PC's own ZK (not the SMSP's).

  FLOW_BR_PC_ZK=host:port overrides the session's default local endpoint.
  """
  from zeus.zookeeper_session import ZookeeperSession
  host_port = os.environ.get("FLOW_BR_PC_ZK")
  session = (ZookeeperSession(host_port_list=host_port) if host_port
             else ZookeeperSession())
  if not session.wait_for_connection(timeout=timeout):
    raise RuntimeError("failed to connect to PC Zookeeper%s"
                       % (" at %s" % host_port if host_port else ""))
  return session


def read_zk_json(zk, path):
  raw = zk_bytes(zk.get(path))
  if not raw:
    return None
  return json.loads(raw.decode("utf-8"))


def update_field_br_status(mutate, create=False):
  """Read-modify-write the status node with mutate(status) -> None.

  Without create=True a missing node is left alone: backups run before
  install.sh (or after `flow-br disable` removed it) do not report status.
  Writers are serialized by the flow-br backup lock, and install/disable are
  operator actions, so there is no compare-and-set.
  """
  zk = connect_pc_zk()
  try:
    status = read_zk_json(zk, FIELD_BR_ZK_PATH)
    if status is None:
      if not create:
        return False
      status = {}
    mutate(status)
    status["version"] = FIELD_BR_STATUS_VERSION
    zk_set(zk, FIELD_BR_ZK_PATH,
           json.dumps(status, sort_keys=True).encode("utf-8"))
    return True
  finally:
    zk.close()


def report_status(mutate, what):
  """Best-effort status write; a ZK problem must not fail the backup."""
  try:
    update_field_br_status(mutate)
  except Exception as ex:
    print("[status] WARN: could not record %s in PC ZK: %s" % (what, ex))


def record_attempt_start():
  def mutate(status):
    status["attempt_started_usecs"] = now_usecs()
    status["last_attempt_status"] = "RUNNING"
  report_status(mutate, "backup start")


def record_attempt_success(archive):
  def mutate(status):
    ts = now_usecs()
    status["last_attempt_usecs"] = ts
    status["last_attempt_status"] = "SUCCEEDED"
    status["last_success_usecs"] = ts
    status["last_archive"] = archive
    status["consecutive_failures"] = 0
    status["last_error_code"] = ""
    status["last_error"] = ""
  report_status(mutate, "backup success")


def record_attempt_failure(code, message):
  def mutate(status):
    status["last_attempt_usecs"] = now_usecs()
    status["last_attempt_status"] = "FAILED"
    status["consecutive_failures"] = int(
        status.get("consecutive_failures", 0)) + 1
    status["last_error_code"] = code
    status["last_error"] = short_error(message)
  report_status(mutate, "backup failure")


def record_attempt_skipped(reason):
  def mutate(status):
    status["last_attempt_usecs"] = now_usecs()
    status["last_attempt_status"] = "SKIPPED"
    status["last_skip_reason"] = short_error(reason)
  report_status(mutate, "skipped backup")


def get_pc_version():
  """Running PC version (e.g. pc.7.5), or None if it cannot be read."""
  try:
    from util.cluster.version import get_prism_central_version
    return get_prism_central_version()
  except Exception:
    return None


def version_train(version):
  """'pc.7.5.0.1' -> 'pc.7.5'; None for unparsable versions."""
  parts = (version or "").split(".")
  if len(parts) < 3:
    return None
  return ".".join(parts[:3])


# Some types (atlas_security_group, port_set, flex_security_group,
# atlas_port_set_address_set_map) are is_evictable and IDF rejects unbounded
# reads of them with 1018 kGetAllEvictableEntitiesUnsupported. Every read is
# therefore a bounded query for ids, then GetEntities on those ids.
def all_rows_predicate():
  """Tautology WHERE clause, only to make the read bounded."""
  master = COL("_master_cluster_uuid_")
  return OR(EXISTS(master), NOT(EXISTS(master)))


def list_entity_ids(cpdb, table):
  ret = cpdb.query(QUERY("atlas:flow_br_poc.list_entity_ids", FROM=table,
                         WHERE=all_rows_predicate()))
  if not ret.total_group_count or not ret.group_results_list:
    return []
  return [raw.entity_guid.entity_id
          for raw in ret.group_results_list[0].raw_results]


def read_entities(cpdb, table, metadata_only=False):
  entity_ids = list_entity_ids(cpdb, table)
  entities = []
  for start in range(0, len(entity_ids), GET_ENTITIES_BATCH):
    guid_list = [
        insights_interface_pb2.EntityGuid(entity_type_name=table,
                                          entity_id=entity_id)
        for entity_id in entity_ids[start:start + GET_ENTITIES_BATCH]]
    # Rows deleted between the query and this read come back as None.
    entities.extend(entity for entity in cpdb.get_entities(
        guid_list, metadata_only=metadata_only, include_deleted=False)
                    if entity is not None)
  return entities


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #
class ArchiveSink(object):
  """File-like target for the streamed tar: hashes and forwards every chunk."""

  def __init__(self, outputs):
    self.outputs = outputs
    self.sha256 = hashlib.sha256()
    self.size = 0

  def write(self, data):
    self.sha256.update(data)
    self.size += len(data)
    for out in self.outputs:
      out.write(data)
    return len(data)

  def flush(self):
    for out in self.outputs:
      out.flush()


def add_member(tar, name, data):
  info = tarfile.TarInfo(name)
  info.size = len(data)
  info.mtime = int(time.time())
  info.mode = 0o644
  tar.addfile(info, io.BytesIO(data))


def dump_table(cpdb, table):
  """<table>'s rows as base64 protobuf lines: (bytes or None if empty, count).

  Read errors propagate so that a partial backup is never published.
  """
  entities = read_entities(cpdb, table)
  if not entities:
    return None, 0
  return (b"".join(base64.b64encode(entity.SerializeToString()) + b"\n"
                   for entity in entities), len(entities))


def backup_zk(args):
  """Snapshot ZK_BACKUP_ROOTS as JSON: (bytes, node count, endpoint)."""
  endpoint = resolve_zk_endpoint(args)
  if not endpoint:
    raise SystemExit("no SMSP ZK endpoint: pass --smsp-uuid or --zk-host-port. "
                     "Without the default quarantine policy uuids a restore "
                     "duplicates the quarantine policies.")

  print("[backup] ZK endpoint %s" % endpoint)
  zk = connect_zk(endpoint)
  try:
    nodes = {}
    for root in ZK_BACKUP_ROOTS:
      before = len(nodes)
      zk_dump_tree(zk, root, nodes)
      print("  [backup] zk %-38s %5d nodes" % (root, len(nodes) - before))
  finally:
    zk.close()

  for path in ZK_RESTORE_PATHS:
    node = nodes.get(path)
    print("  [backup] zk %-62s %s"
          % (path, node["text"] if node else "<absent>"))
  data = json.dumps({"endpoint": endpoint, "roots": ZK_BACKUP_ROOTS,
                     "nodes": nodes}, indent=2, sort_keys=True)
  return data.encode("utf-8"), len(nodes), endpoint


def remote_path(path):
  """Shell-quote a remote path, keeping a leading ~ expandable."""
  if path == "~":
    return '"$HOME"'
  if path.startswith("~/"):
    return '"$HOME"/' + shlex.quote(path[2:])
  return shlex.quote(path)


def ssh_command(args, remote_cmd):
  """Non-interactive ssh with the dedicated key and a pinned host key.

  -F /dev/null keeps the PCVM's own ssh config (control masters, cluster keys)
  out of the picture.
  """
  return ["ssh", "-F", "/dev/null", "-i", args.ssh_key,
          "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
          "-o", "StrictHostKeyChecking=yes",
          "-o", "UserKnownHostsFile=%s" % args.known_hosts,
          "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15",
          "-o", "ServerAliveCountMax=4", "-o", "LogLevel=ERROR",
          "%s@%s" % (args.scp_user, args.scp_host), remote_cmd]


def check_ssh_files(args):
  if not os.path.exists(args.ssh_key):
    raise SystemExit("ssh key %s not found; create it with: ssh-keygen -t rsa "
                     "-b 4096 -f %s -N ''" % (args.ssh_key, args.ssh_key))
  # ssh-keyscan cannot be used on the PCVM: in FIPS mode it only offers the
  # disallowed curve25519 key exchange and returns no keys.
  if not os.path.exists(args.known_hosts):
    raise SystemExit("pinned host key file %s not found. On %s run: awk -v "
                     "h=%s '{print h, $1, $2}' /etc/ssh/ssh_host_ecdsa_key.pub "
                     "and save the output on this PCVM as %s"
                     % (args.known_hosts, args.scp_host, args.scp_host,
                        args.known_hosts))


def publish_remote(args, remote_dir, name, digest):
  """Verify <name>.part against <digest>, then rename it into place.

  The rename is atomic, so a reader of <remote_dir> only ever sees complete,
  verified archives. <name>.sha256 is written for `sha256sum -c`.
  """
  cmd = ("cd %s && printf '%%s  %%s\\n' %s %s.part | sha256sum -c --status && "
         "mv -f %s.part %s && printf '%%s  %%s\\n' %s %s > %s.sha256"
         % (remote_dir, digest, name, name, name, digest, name, name))
  if subprocess.call(ssh_command(args, cmd)) != 0:
    raise RuntimeError("remote checksum verification or rename failed for %s"
                       % name)


def write_archive(args, cpdb, tables, sink, name, stamp):
  """Stream tables, the ZK snapshot and the manifest into one tar.gz.

  Tables are fetched and written one at a time, so only the largest table is
  ever held in memory and nothing is staged on disk.
  """
  counts = {}
  with tarfile.open(fileobj=sink, mode="w|gz") as tar:
    for table in tables:
      data, count = dump_table(cpdb, table)
      print("  [backup] %-42s %5d %s"
            % (table, count, "empty" if data is None else "streamed"))
      if data is not None:
        add_member(tar, "%s.b64" % table, data)
        counts[table] = count
    zk_data, zk_count, zk_endpoint = backup_zk(args)
    add_member(tar, ZK_JSON_NAME, zk_data)
    manifest = {
        "format_version": 1,
        "archive": name,
        "created_utc": stamp,
        "smsp_uuid": args.smsp_uuid,
        "idf_endpoint": "%s:%d" % (args.idf_ip, args.idf_port),
        "zk_endpoint": zk_endpoint,
        "pc_host": socket.gethostname(),
        "pc_version": get_pc_version(),
        "script_version": SCRIPT_VERSION,
        "tables": counts,
        "entity_count": sum(counts.values()),
        "zk_node_count": zk_count,
    }
    add_member(tar, MANIFEST_NAME,
               json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
  print("[backup] archive %s: %d entities across %d/%d tables, %d ZK nodes"
        % (name, manifest["entity_count"], len(counts), len(tables), zk_count))


def cmd_backup(args):
  stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
  name = "flow_backup_%s_%s.tar.gz" % (args.smsp_uuid or "smsp", stamp)
  local_path = None
  if args.scp_host:
    check_ssh_files(args)
  if not args.scp_host or args.keep_local:
    os.makedirs(args.out_dir, exist_ok=True)
    local_path = os.path.join(args.out_dir, name)
  cpdb = connect_cpdb(args.idf_ip, args.idf_port)
  tables = ([t.strip() for t in args.tables.split(",") if t.strip()]
            if args.tables else SMSP_ENTITY_TYPES)

  remote_dir = remote_path(args.scp_path)
  remote_part = "%s/%s.part" % (remote_dir, name)
  local_fh = upload = None
  upload_err = tempfile.TemporaryFile()
  outputs = []
  try:
    if local_path:
      local_fh = open(local_path + ".part", "wb")
      outputs.append(local_fh)
    if args.scp_host:
      upload = subprocess.Popen(
          ssh_command(args, "mkdir -p %s && cat > %s"
                      % (remote_dir, remote_part)),
          stdin=subprocess.PIPE, stderr=upload_err)
      outputs.append(upload.stdin)
    sink = ArchiveSink(outputs)
    try:
      write_archive(args, cpdb, tables, sink, name, stamp)
    except (BrokenPipeError, ConnectionResetError):
      if upload is None:
        raise
      upload.wait()
      upload_err.seek(0)
      stderr = upload_err.read().decode("utf-8", "replace")
      raise BackupError(classify_ssh_failure(upload.returncode, stderr),
                        "upload to %s aborted: %s" % (args.scp_host, stderr))
    digest = sink.sha256.hexdigest()

    if upload:
      upload.stdin.close()
      if upload.wait() != 0:
        upload_err.seek(0)
        stderr = upload_err.read().decode("utf-8", "replace")
        raise BackupError(classify_ssh_failure(upload.returncode, stderr),
                          "upload to %s failed (ssh exit %d): %s"
                          % (args.scp_host, upload.returncode, stderr))
      publish_remote(args, remote_dir, name, digest)
      print("[backup] uploaded %s@%s:%s/%s (%d bytes, sha256 %s)"
            % (args.scp_user, args.scp_host, args.scp_path, name, sink.size,
               digest))
    if local_fh:
      local_fh.close()
      os.rename(local_path + ".part", local_path)
      print("[backup] local copy %s (%d bytes, sha256 %s)"
            % (local_path, sink.size, digest))
  except BaseException:
    if upload:
      try:
        upload.stdin.close()
      except OSError:
        pass
      if upload.poll() is None:
        upload.kill()
      upload.wait()
      subprocess.call(ssh_command(args, "rm -f %s" % remote_part))
    if local_fh:
      local_fh.close()
      if os.path.exists(local_path + ".part"):
        os.remove(local_path + ".part")
    print("[backup] FAILED: nothing was published")
    raise
  finally:
    upload_err.close()
  args.published_archive = name
  return 0


def preflight_remote(args):
  """Check the backup host accepts the key and the backup dir is writable."""
  remote_dir = remote_path(args.scp_path)

  def check():
    proc = subprocess.run(
        ssh_command(args, "mkdir -p %s && test -w %s" % (remote_dir, remote_dir)),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
      stderr = proc.stderr.decode("utf-8", "replace")
      raise BackupError(classify_ssh_failure(proc.returncode, stderr),
                        "backup host %s@%s:%s: %s"
                        % (args.scp_user, args.scp_host, args.scp_path,
                           stderr.strip() or "exit %d" % proc.returncode))
  with_retries(check, RETRY_DELAYS_SECS, "backup host check")


def preflight_smsp(args):
  """Check SMSP IDF and ZK answer over iKat before streaming anything."""
  def check_idf():
    try:
      with socket.create_connection((args.idf_ip, args.idf_port), timeout=20):
        pass
    except OSError as ex:
      raise BackupError(ERR_SMSP_IDF_UNREACHABLE, "SMSP IDF %s:%d: %s"
                        % (args.idf_ip, args.idf_port, ex))

  def check_zk():
    endpoint = resolve_zk_endpoint(args)
    if not endpoint:
      return
    try:
      connect_zk(endpoint, timeout=30).close()
    except RuntimeError as ex:
      raise BackupError(ERR_SMSP_ZK_UNREACHABLE, str(ex))

  with_retries(check_idf, SMSP_RETRY_DELAYS_SECS, "SMSP IDF check")
  with_retries(check_zk, SMSP_RETRY_DELAYS_SECS, "SMSP ZK check")


def run_backup(args):
  """Backup with retries, recording the outcome in the PC ZK status node.

  Exit codes: 0 success, 2 backup failed (status recorded).
  """
  record_attempt_start()
  try:
    try:
      ensure_idf_ikat(args)
      resolve_smsp_endpoints(args)
    except SystemExit as ex:
      raise BackupError(ERR_SMSP_IDF_UNREACHABLE,
                        str(ex) if str(ex) else str(ex.code))
    except subprocess.CalledProcessError as ex:
      raise BackupError(ERR_SMSP_IDF_UNREACHABLE, str(ex))
    if args.scp_host:
      try:
        check_ssh_files(args)
      except SystemExit as ex:
        raise BackupError(ERR_CONFIG_INVALID,
                          str(ex) if str(ex) else str(ex.code))
    preflight_smsp(args)
    if args.scp_host:
      preflight_remote(args)

    def attempt():
      try:
        return cmd_backup(args)
      except BackupError:
        raise
      except Exception as ex:
        raise BackupError(ERR_BACKUP_FAILED, "%s: %s"
                          % (type(ex).__name__, ex))
    with_retries(attempt, RETRY_DELAYS_SECS[:1], "backup")
  except BackupError as ex:
    print("[backup] FAILED %s at %s: %s"
          % (ex.code, format_usecs_utc(now_usecs()), short_error(ex)))
    record_attempt_failure(ex.code, str(ex))
    return 2
  except KeyboardInterrupt:
    record_attempt_failure(ERR_BACKUP_FAILED, "interrupted")
    raise
  archive = getattr(args, "published_archive", "")
  record_attempt_success(archive)
  print("[backup] status SUCCEEDED at %s%s"
        % (format_usecs_utc(now_usecs()),
           (" archive=%s" % archive) if archive else ""))
  return 0


def check_manifest_versions(args):
  """Refuse to restore an archive from a different PC release train."""
  manifest_path = os.path.join(args.work_dir, MANIFEST_NAME)
  if not os.path.exists(manifest_path):
    return
  with open(manifest_path) as fh:
    manifest = json.load(fh)
  backed_up = version_train(manifest.get("pc_version"))
  running = version_train(get_pc_version())
  if not backed_up or not running:
    print("[restore] WARN: PC version unknown (archive: %s, running: %s); "
          "skipping version check" % (manifest.get("pc_version"),
                                      get_pc_version()))
    return
  if backed_up == running:
    print("[restore] archive PC version %s matches running PC"
          % manifest.get("pc_version"))
    return
  if args.allow_version_mismatch:
    print("[restore] WARN: archive taken on %s, running %s; continuing "
          "(--allow-version-mismatch)" % (backed_up, running))
    return
  raise SystemExit("archive was taken on %s but this PC runs %s; restoring "
                   "across PC versions is not validated. Re-run with "
                   "--allow-version-mismatch to override."
                   % (backed_up, running))


# --------------------------------------------------------------------------- #
# Status commands (used by install.sh / flow-br)
# --------------------------------------------------------------------------- #
def cmd_zk_status(args):
  zk = connect_pc_zk()
  try:
    status = read_zk_json(zk, FIELD_BR_ZK_PATH)
    timers = {}
    for node in (zk.list(FIELD_BR_TIMER_ZK_DIR) or []):
      timers[node] = read_zk_json(zk, "%s/%s" % (FIELD_BR_TIMER_ZK_DIR, node))
  finally:
    zk.close()
  # ZK stores usecs for Atlas; print sibling *_utc fields for operators.
  print(json.dumps(with_human_times({"status": status, "timers": timers}),
                   indent=2, sort_keys=True))
  return 0


def cmd_zk_init(args):
  def mutate(status):
    status["enabled"] = True
    status["install_path"] = args.install_path
    status["backup_node_ip"] = args.backup_node_ip
    status["interval_secs"] = args.interval_secs
    status.setdefault("installed_usecs", now_usecs())
    status.setdefault("consecutive_failures", 0)
  update_field_br_status(mutate, create=True)
  print("[status] %s: enabled, backup node %s, interval %ds (%s)"
        % (FIELD_BR_ZK_PATH, args.backup_node_ip, args.interval_secs,
           format_usecs_utc(now_usecs())))
  return 0


def cmd_zk_disable(args):
  def mutate(status):
    status["enabled"] = False
  if update_field_br_status(mutate):
    print("[status] %s: disabled" % FIELD_BR_ZK_PATH)
  else:
    print("[status] %s: not present" % FIELD_BR_ZK_PATH)
  return 0


def cmd_zk_skip(args):
  record_attempt_skipped(args.reason)
  return 0


def cmd_zk_timer(args):
  heartbeat = {"healthy": bool(args.healthy), "checked_usecs": now_usecs(),
               "next_fire_usecs": args.next_fire_usecs or 0,
               "detail": short_error(args.detail or "")}
  zk = connect_pc_zk()
  try:
    zk_set(zk, "%s/%s" % (FIELD_BR_TIMER_ZK_DIR, args.node_ip),
           json.dumps(heartbeat, sort_keys=True).encode("utf-8"))
  finally:
    zk.close()
  return 0


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #
def get_non_nested_attr_names(cpdb, entity_type_name):
  """Attribute names that can be written directly.

  Nested-field-derived columns are computed by IDF and reject writes with
  kNestedFieldDirectUpdatesNotAllowed.
  """
  entity_type = cpdb.get_entity_type(entity_type_name)
  names = set()
  if entity_type is not None:
    for metric_type in entity_type.metric_type_list:
      if (metric_type.is_attribute and
          not metric_type.HasField("nested_field_info")):
        names.add(metric_type.metric_name)
  return names


def read_local_rows(cpdb, table):
  """{entity_id -> metadata Entity} for <table>'s local rows."""
  try:
    entities = read_entities(cpdb, table, metadata_only=True)
  except Exception as ex:  # noqa: BLE001 - unknown table on the target
    print("  [restore] %-30s WARN: local read failed (%s); treating as empty, "
          "so nothing will be flushed for this table" % (table, ex))
    return {}
  return {e.entity_guid.entity_id: e for e in entities}


def delete_row(cpdb, entity):
  cpdb.delete_entity(entity, is_cas_entity=entity.HasField("cas_value"))


def flush_table(cpdb, table, protected_ids):
  """Delete <table>'s local rows except protected_ids (rows another cluster,
  e.g. a PE, masters)."""
  deleted = 0
  for entity_id, entity in read_local_rows(cpdb, table).items():
    if entity_id in protected_ids:
      continue
    delete_row(cpdb, entity)
    deleted += 1
  return deleted


def normalize_uuid(value):
  if not value:
    return ""
  if isinstance(value, (bytes, bytearray)):
    value = value.hex()
  return str(value).replace("-", "").lower()


def read_replica_state(replica_cpdb, table, entity_ids):
  """{entity_id -> (incarnation_id, master uuid)} from the PC replica.

  include_deleted=True so tombstones count: their incarnation still has to be
  exceeded.
  """
  if replica_cpdb is None or not entity_ids:
    return {}
  guid_list = [
      insights_interface_pb2.EntityGuid(entity_type_name=table, entity_id=eid)
      for eid in entity_ids]
  try:
    entities = replica_cpdb.get_entities(guid_list, metadata_only=True,
                                         include_deleted=True)
  except Exception as ex:  # noqa: BLE001 - best effort; fall back to backup value
    print("  [restore] %-30s WARN: replica read failed (%s); falling back to "
          "backup incarnation and skipping ownership checks" % (table, ex))
    return {}
  found = {}
  for entity_id, entity in zip(entity_ids, entities):
    if entity is not None:
      found[entity_id] = (entity.incarnation_id,
                          normalize_uuid(entity.master_cluster_uuid))
  return found


def is_foreign_owned(replica_master, owner_uuids):
  """True if the PC replica says a cluster outside owner_uuids masters it.

  The backup cannot tell: on the SMSP every row looks native. Restoring a
  foreign row with a bumped incarnation would steal it from its real owner.
  """
  if not replica_master or not owner_uuids:
    return False
  return replica_master not in owner_uuids


def flush_replay_minted_table(cpdb, replica_cpdb, table, dry_run, owner_uuids):
  """Flush the fresh SMSP's rows for a REPLAY_MINTED_TABLES table, attach
  nothing; replay re-creates them."""
  local_rows = read_local_rows(cpdb, table)
  replica_state = read_replica_state(replica_cpdb, table,
                                     sorted(local_rows))
  protected_ids = {
      entity_id for entity_id in replica_state
      if is_foreign_owned(replica_state[entity_id][1], owner_uuids)}
  removable = len(set(local_rows) - protected_ids)
  if dry_run:
    print("  [restore] %-30s WOULD flush %5d replay-minted entities "
          "(%d protected)" % (table, removable,
                              len(protected_ids & set(local_rows))))
    return 0
  removed = flush_table(cpdb, table, protected_ids)
  print("  [restore] %-30s flushed %5d replay-minted entities "
        "(%d protected); replay will recreate them" %
        (table, removed, len(protected_ids & set(local_rows))))
  return removed


def restore_table(cpdb, table, work_dir, dry_run, flush, is_cas,
                  replica_cpdb=None, owner_uuids=None):
  """Attach entities from <table>.b64 into the local IDF.

  attach_entity requires an incarnation_id greater than the previous one, and
  the PC replica drops rows whose incarnation is lower than what it holds, so
  incarnation_id = max(backup, PC replica) + 1. The replica value covers a
  previous restore attempt having already bumped it.
  """
  src_path = os.path.join(work_dir, "%s.b64" % table)
  if not os.path.exists(src_path):
    return 0

  allowed = get_non_nested_attr_names(cpdb, table)
  if not allowed:
    print("  [restore] %-30s SKIPPED: entity type not found on target or has "
          "no writable attributes" % table)
    return 0

  entities = []
  with open(src_path) as fh:
    for line in fh:
      line = line.strip()
      if not line:
        continue
      entity = insights_interface_pb2.Entity()
      entity.ParseFromString(base64.b64decode(line))
      entities.append(entity)

  local_rows = read_local_rows(cpdb, table)
  replica_state = read_replica_state(
      replica_cpdb, table,
      sorted(set([e.entity_guid.entity_id for e in entities]) |
             set(local_rows)))
  protected_ids = {
      entity_id for entity_id in replica_state
      if is_foreign_owned(replica_state[entity_id][1], owner_uuids)}

  if flush and not dry_run:
    removed = flush_table(cpdb, table, protected_ids)
    print("  [restore] %-30s flushed %5d pre-existing entities (%d protected)" %
          (table, removed, len(protected_ids & set(local_rows))))
    local_rows = read_local_rows(cpdb, table)

  count = 0
  skipped = 0
  for entity in entities:
    entity_id = entity.entity_guid.entity_id
    replica_value, replica_master = replica_state.get(entity_id, (0, ""))
    if entity_id in protected_ids:
      print("      %s SKIPPED: replica masters it under %s (foreign cluster)"
            % (entity_id, replica_master))
      skipped += 1
      continue
    # CAS mode is fixed at creation; attaching in the other mode fails with
    # kCasUpdateForNonCasEntity, so drop the mismatched row first.
    local = local_rows.get(entity_id)
    if local is not None and local.HasField("cas_value") != is_cas and not dry_run:
      delete_row(cpdb, local)
      print("      %s deleted stale %s row to switch CAS mode"
            % (entity_id, "CAS" if local.HasField("cas_value") else "non-CAS"))
    attributes = {name: value
                  for name, value in
                  cpdb_utils.get_entity_attribute_data_map(entity).items()
                  if name in allowed}
    incarnation_id = max(entity.incarnation_id, replica_value) + 1
    source = "max(backup=%d, replica=%d)+1" % (entity.incarnation_id,
                                               replica_value)
    if not dry_run:
      cpdb.attach_entity(table, entity_id, attributes, full_update=True,
                         is_cas_entity=is_cas, incarnation_id=incarnation_id,
                         overwrite_replicated_tombstones=True)
    print("      %s %sincarnation=%d  [%s]"
          % (entity_id, "WOULD attach " if dry_run else "", incarnation_id,
             source))
    count += 1
  print("  [restore] %-30s %5d entities %s, %d skipped -> %s"
        % (table, count, "to attach" if dry_run else "attached", skipped, table))
  return count


def restore_zk(args):
  """Write ZK_RESTORE_PATHS from the snapshot into SMSP ZK.

  Must run before replay restarts Kratos: its default policy manager reads
  these uuids at startup and re-creates any quarantine policy they miss.
  """
  json_path = os.path.join(args.work_dir, ZK_JSON_NAME)
  if not os.path.exists(json_path):
    print("[restore] ZK SKIPPED: no %s in the tar (backup ran without a ZK "
          "endpoint), so Kratos will re-create its default quarantine "
          "policies next to the restored ones" % ZK_JSON_NAME)
    return 0

  endpoint = resolve_zk_endpoint(args)
  if not endpoint:
    print("[restore] ZK SKIPPED: %s is present but no --smsp-uuid/--zk-host-port "
          "was given for the REBUILT cluster" % ZK_JSON_NAME)
    return 0

  with open(json_path) as fh:
    snapshot = json.load(fh)
  nodes = snapshot.get("nodes", {})
  paths = ([p.strip() for p in args.zk_paths.split(",") if p.strip()]
           if args.zk_paths else ZK_RESTORE_PATHS)
  print("[restore] ZK endpoint %s (snapshot taken from %s)"
        % (endpoint, snapshot.get("endpoint", "?")))

  zk = connect_zk(endpoint)
  written = 0
  try:
    for path in paths:
      node = nodes.get(path)
      if node is None:
        print("  [restore] zk %-62s SKIPPED: absent from snapshot" % path)
        continue
      value = base64.b64decode(node["b64"])
      current = zk_bytes(zk.get(path))
      if current == value:
        print("  [restore] zk %-62s already matches (%s)" % (path, node["text"]))
        continue
      if args.dry_run:
        print("  [restore] zk %-62s WOULD set %s (currently %s)"
              % (path, node["text"], zk_display(current)))
        continue
      action = zk_set(zk, path, value)
      print("  [restore] zk %-62s %s -> %s (was %s)"
            % (path, action, node["text"], zk_display(current)))
      written += 1
  finally:
    zk.close()
  print("[restore] ZK: %d node(s) %s"
        % (written, "to write" if args.dry_run else "written"))
  return written


def resolve_owner_uuids(args):
  """Cluster uuids whose rows the restore may take over.

  Both the backed-up SMSP's uuid (from the manifest) and the rebuilt SMSP's are
  needed: when the rebuilt SMSP got a new uuid, PC may still attribute rows to
  the old one, and once a restore has run they are attributed to the new one.
  With a reused uuid the two are the same.
  """
  if args.owner_uuids:
    return set(normalize_uuid(u) for u in args.owner_uuids.split(",")
               if u.strip())
  manifest_path = os.path.join(args.work_dir, MANIFEST_NAME)
  backed_up = None
  if os.path.exists(manifest_path):
    with open(manifest_path) as fh:
      backed_up = json.load(fh).get("smsp_uuid")
  if not backed_up or not args.smsp_uuid:
    raise SystemExit(
        "cannot derive the owner uuids (backed-up SMSP: %s, rebuilt SMSP: %s); "
        "pass --owner-uuids <backed-up-uuid>,<rebuilt-uuid>, or --smsp-uuid "
        "<rebuilt-uuid> when running inside the SMSP"
        % (backed_up or "not in manifest", args.smsp_uuid or "unknown"))
  print("[restore] owner uuids: backed-up SMSP %s, rebuilt SMSP %s (%s)"
        % (backed_up, args.smsp_uuid,
           "same uuid" if normalize_uuid(backed_up) ==
           normalize_uuid(args.smsp_uuid) else "new uuid"))
  return set([normalize_uuid(backed_up), normalize_uuid(args.smsp_uuid)])


def cmd_restore(args):
  if args.skip_replay:
    return restore_and_replay(args, None)
  # Acquired before any write so a missing mspctl fails before IDF changes.
  with smsp_kubectl() as kubectl:
    return restore_and_replay(args, kubectl)


ARCHIVE_NAME_RE = re.compile(r"^flow_backup_[A-Za-z0-9-]+_\d{8}T\d{6}Z\.tar\.gz$")


class HashingReader(object):
  """File-like source for the streamed tar: hashes every chunk it hands out."""

  def __init__(self, src):
    self.src = src
    self.sha256 = hashlib.sha256()

  def read(self, size=-1):
    data = self.src.read(size)
    self.sha256.update(data)
    return data

  def drain(self):
    while self.read(1 << 16):
      pass


def safe_extract(tar, work_dir):
  """Extract a backup archive: flat regular files only, so a damaged or
  hostile archive cannot write outside work_dir."""
  for member in tar:
    if (not member.isfile() or os.path.basename(member.name) != member.name
        or member.name in ("", ".", "..")):
      raise RuntimeError("unexpected archive member %r" % member.name)
    tar.extract(member, work_dir)


def prepare_work_dir(args):
  """Use an empty --work-dir, or a fresh one; restore reads every .b64 in it,
  so leftovers from another archive would be restored too."""
  if args.work_dir is None:
    args.work_dir = tempfile.mkdtemp(prefix="flow_br_restore_",
                                     dir=os.path.expanduser("~"))
  elif os.path.isdir(args.work_dir) and os.listdir(args.work_dir):
    raise SystemExit("--work-dir %s is not empty; use an empty or new "
                     "directory" % args.work_dir)
  os.makedirs(args.work_dir, exist_ok=True)
  print("[restore] work dir %s" % args.work_dir)


def pick_remote_archive(args, remote_dir):
  if args.archive:
    name = args.archive
  else:
    listing = subprocess.check_output(ssh_command(
        args, "cd %s && ls -1t flow_backup_*.tar.gz 2>/dev/null | head -1"
        % remote_dir)).decode("utf-8").strip()
    if not listing:
      raise SystemExit("no flow_backup_*.tar.gz in %s:%s"
                       % (args.scp_host, args.scp_path))
    name = listing
  if not ARCHIVE_NAME_RE.match(name):
    raise SystemExit("unexpected archive name %r" % name)
  return name


def fetch_remote_archive(args):
  """Stream <archive> from the backup host and extract it into work_dir.

  Nothing but the extracted members lands on the PCVM. The bytes are hashed as
  they arrive and must match <archive>.sha256, which covers corruption at rest
  and in transit; restore only starts after that check.
  """
  check_ssh_files(args)
  remote_dir = remote_path(args.scp_path)
  name = pick_remote_archive(args, remote_dir)
  expected = subprocess.check_output(ssh_command(
      args, "cat %s/%s.sha256" % (remote_dir, name))).decode("utf-8").split()
  if len(expected) != 2 or expected[1] != name:
    raise SystemExit("malformed %s.sha256 on %s" % (name, args.scp_host))
  print("[restore] fetching %s@%s:%s/%s"
        % (args.scp_user, args.scp_host, args.scp_path, name))
  download = subprocess.Popen(ssh_command(args, "cat %s/%s"
                                          % (remote_dir, name)),
                              stdout=subprocess.PIPE)
  reader = HashingReader(download.stdout)
  try:
    with tarfile.open(fileobj=reader, mode="r|gz") as tar:
      safe_extract(tar, args.work_dir)
    reader.drain()
  except BaseException:
    download.kill()
    download.wait()
    raise
  download.stdout.close()
  if download.wait() != 0:
    raise RuntimeError("download from %s failed (ssh exit %d)"
                       % (args.scp_host, download.returncode))
  digest = reader.sha256.hexdigest()
  if digest != expected[0]:
    raise RuntimeError("checksum mismatch for %s: got %s, expected %s"
                       % (name, digest, expected[0]))
  print("[restore] sha256 %s verified" % digest)


def restore_and_replay(args, kubectl):
  prepare_work_dir(args)
  if args.scp_host:
    fetch_remote_archive(args)
  else:
    with tarfile.open(args.in_tar, "r:gz") as tar:
      safe_extract(tar, args.work_dir)
  check_manifest_versions(args)
  owner_uuids = resolve_owner_uuids(args)
  restore_zk(args)
  cpdb = connect_cpdb(args.idf_ip, args.idf_port)
  # Read-only: supplies current incarnation (incl. tombstones) and ownership.
  replica_cpdb = connect_cpdb(args.replica_idf_ip, args.replica_idf_port)
  total = 0
  backup_tables = {n[:-4] for n in os.listdir(args.work_dir)
                   if n.endswith(".b64")}
  only = set(t.strip() for t in args.tables.split(",")) if args.tables else None
  minted = set() if args.restore_replay_minted else set(REPLAY_MINTED_TABLES)
  # Replay-minted tables can be empty in the backup yet populated on the fresh
  # SMSP, so they are flushed even without a .b64 file.
  tables = sorted(backup_tables | (minted if only is None else minted & only))
  for table in tables:
    if only and table not in only:
      continue
    if table in minted:
      flush_replay_minted_table(cpdb, replica_cpdb, table, args.dry_run,
                                owner_uuids)
      continue
    total += restore_table(cpdb, table, args.work_dir, args.dry_run,
                           not args.no_flush, is_cas=not args.non_cas,
                           replica_cpdb=replica_cpdb,
                           owner_uuids=owner_uuids)
  mode = "dry-run (no writes)" if args.dry_run else "written to IDF"
  print("[restore] done: %d entities, %s" % (total, mode))
  if not args.skip_replay:
    run_replay(args, kubectl, cpdb)
  return 0


# --------------------------------------------------------------------------- #
# Replay
# --------------------------------------------------------------------------- #
# Restoring IDF does not program ANC/PolicyDB. The SMSP's CMSP->SMSP migration
# recovery does: with migration=STARTED, Atlas (SmspRecoveryManager) replays
# subnets/VPCs/ports into ANC and marks DEPENDENCY_RECOVERY_ZK, then Kratos
# replays address/entity groups and policies and sets RECOVERY_STATUS_ZK to
# RECOVERED, and Atlas finally sets migration=RECOVERY_COMPLETED. Both read
# migration only when they start, hence the restart.
MIGRATION_ZK = "/appliance/logical/flow_smsp/migration"
RECOVERY_STATUS_ZK = "/appliance/logical/flow_smsp/flow_anc_recovery_status"
DEPENDENCY_RECOVERY_ZK = (
    "/appliance/logical/atlas/smsp_flow_dependency_entities_recovery_complete")
REPLAY_DEPLOYMENTS = ["atlas", "kratos"]
SMSP_NAMESPACE = "ntnx-flow"
POLICYDB_POD = "anc-policydb-0"
POLICYDB_SOCKET = "unix:/var/run/ovs/ovs-policy-config.sock"
POLICYDB_DB = "ANC_PolicyConfig"
POLICYDB_CT_TABLE = "CT_Mapping"
# ANC intent API; Atlas reaches it with the same URL and certs (atlas_config).
HERMES_URL = "https://anc-hermes-service:4801"
HERMES_CERTS = ["--cert", "/etc/ssl/cert", "--key", "/etc/ssl/key",
                "--cacert", "/etc/ssl/ca.pem"]
ATLAS_POD_SELECTOR = "app.kubernetes.io/name=atlas"


@contextlib.contextmanager
def smsp_kubectl(namespace=SMSP_NAMESPACE):
  """Yield kubectl(*args) bound to a namespace on the Flow SMSP.

  Default is ntnx-flow (Atlas/ANC). Pass ntnx-ikat for the SMSP-side iKat
  ConfigMap and DaemonSet.
  """
  try:
    kubeconfig = subprocess.check_output(
        [MSPCTL, "cluster", "kubeconfig", "flow"], stderr=subprocess.DEVNULL)
  except (OSError, subprocess.CalledProcessError) as ex:
    raise SystemExit("needs kubectl access to the SMSP via %s (%s); run on a "
                     "PCVM, or pass --idf-ip / --skip-replay as appropriate"
                     % (MSPCTL, ex))
  with tempfile.NamedTemporaryFile(prefix="flow_br_kc_", suffix=".yaml") as fh:
    fh.write(kubeconfig)
    fh.flush()
    env = dict(os.environ, KUBECONFIG=fh.name)

    def kubectl(*cmd):
      try:
        return subprocess.check_output(
            ["kubectl", "-n", namespace] + list(cmd), env=env,
            stderr=subprocess.PIPE).decode("utf-8")
      except subprocess.CalledProcessError as ex:
        err = (ex.stderr or b"").decode("utf-8", "replace").strip()
        raise SystemExit("kubectl -n %s %s failed: %s"
                         % (namespace, " ".join(cmd), err or ex))
    yield kubectl


def policydb_transact(kubectl, op):
  out = kubectl("exec", POLICYDB_POD, "-c", "anc-policydb", "--",
                "ovsdb-client", "transact", POLICYDB_SOCKET,
                json.dumps([POLICYDB_DB, op]))
  result = json.loads(out)[0]
  if "error" in result:
    raise RuntimeError("PolicyDB %s failed: %s" % (op["op"], result))
  return result


def cleanup_policydb(kubectl, cpdb, dry_run):
  """Delete CT_Mapping rows whose policy is not in SMSP IDF.

  The fresh SMSP's own default policies leave mappings behind: restore flushes
  those policies from IDF, but replay only adds mappings (create_if_not_exists)
  and nothing sweeps orphans. Flow itself deletes CT_Mapping rows directly
  (PolicyDbManager.delete_by_uuids), so deleting them here is equivalent.
  """
  rows = policydb_transact(kubectl, {
      "op": "select", "table": POLICYDB_CT_TABLE, "where": [],
      "columns": ["nsp_uuid"]})["rows"]
  mapped = {}
  for row in rows:
    mapped[row["nsp_uuid"]] = mapped.get(row["nsp_uuid"], 0) + 1
  live = set(list_entity_ids(cpdb, "network_security_policy"))
  orphans = sorted(set(mapped) - live)
  print("[replay] PolicyDB: %d CT_Mapping rows for %d policies, %d orphaned"
        % (len(rows), len(mapped), len(orphans)))
  for nsp_uuid in orphans:
    if dry_run:
      print("  [replay] WOULD delete %d CT_Mapping rows of nsp_uuid %s"
            % (mapped[nsp_uuid], nsp_uuid))
      continue
    count = policydb_transact(kubectl, {
        "op": "delete", "table": POLICYDB_CT_TABLE,
        "where": [["nsp_uuid", "==", nsp_uuid]]}).get("count", 0)
    print("  [replay] deleted %d CT_Mapping rows of nsp_uuid %s"
          % (count, nsp_uuid))


def decode_zproto(entity, proto_cls):
  column = cpdb_utils.get_entity_attribute_data_map(entity).get(
      "__zprotobuf__")
  if column is None:
    return None
  raw = (column.bytes_value if column.HasField("bytes_value")
         else column.str_value)
  if isinstance(raw, str):
    raw = raw.encode("latin-1")
  proto = proto_cls()
  proto.ParseFromString(zlib.decompress(raw))
  return proto


def hermes_request(kubectl, atlas_pod, method, path):
  """(status, body) of a Hermes REST call, sent from the SMSP atlas pod."""
  out = kubectl("exec", atlas_pod, "--", "curl", "-s", "-X", method,
                *HERMES_CERTS, "-w", "\n%{http_code}",
                "%s/%s" % (HERMES_URL, path))
  body, _, status = out.rpartition("\n")
  return int(status), body


def expected_hermes_intents(cpdb):
  """Intent ids that SMSP IDF accounts for, per Hermes resource type."""
  from atlas.atlas_types_pb2 import AtlasPortSetAddressSetMap

  port_sets = set(list_entity_ids(cpdb, "atlas_port_set"))
  address_sets = set()
  for entity in read_entities(cpdb, "atlas_port_set_address_set_map"):
    proto = decode_zproto(entity, AtlasPortSetAddressSetMap)
    if proto is not None:
      address_sets.update(
          x for x in (proto.generated_mac_address_set_uuid,
                      proto.generated_ipv4_address_set_uuid,
                      proto.generated_ipv6_address_set_uuid) if x)
  for table in ("network_address_group", "network_entity_group"):
    for owner in list_entity_ids(cpdb, table):
      for family in ("IPv4", "IPv6"):
        address_sets.add(str(uuid.uuid5(uuid.UUID(owner), family)))
  return {
      "security_group": set(list_entity_ids(cpdb, "atlas_security_group")),
      "port_set": port_sets,
      "address_set": address_sets,
  }


def cleanup_hermes(kubectl, cpdb, dry_run):
  """Delete ANC intents left by the fresh SMSP's own default policies.

  Before the restore, the fresh SMSP programmed its default quarantine
  policies into ANC: a security group, a port set and the port set's generated
  address sets each. Restore flushes their IDF rows, and Atlas deletes intents
  only from its delete tasks, which require the IDF row; replay only pushes.
  These are the same DELETE calls AncController.delete_* makes.

  Address sets have no IDF table; Kratos creates AG/EG ones (uuid5) directly.
  Only random (uuid4) sets, i.e. port-set-generated ones, that no live port
  set maps to and no live security group references are deleted.
  """
  atlas_pod = kubectl("get", "pod", "-l", ATLAS_POD_SELECTOR, "-o",
                      "jsonpath={.items[0].metadata.name}").strip()
  expected = expected_hermes_intents(cpdb)
  if not expected["security_group"] or not expected["port_set"]:
    print("[replay] Hermes: SMSP IDF lists no security groups or port sets; "
          "skipping cleanup")
    return

  intents = {}
  for kind in ("security_group", "port_set", "address_set"):
    status, body = hermes_request(kubectl, atlas_pod, "GET", "v1/%s" % kind)
    if status != 200:
      raise RuntimeError("Hermes GET v1/%s returned %d: %s"
                         % (kind, status, body[:200]))
    intents[kind] = json.loads(body).get("intent_list", [])

  live_sg_refs = set()
  for intent in intents["security_group"]:
    if intent["id"] in expected["security_group"]:
      live_sg_refs.update(re.findall(
          r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
          json.dumps(intent.get("spec", {}))))

  stale = {}
  for kind in ("security_group", "port_set"):
    stale[kind] = sorted(i["id"] for i in intents[kind]
                         if i["id"] not in expected[kind])
  stale["address_set"] = sorted(
      i["id"] for i in intents["address_set"]
      if i["id"] not in expected["address_set"]
      and i["id"] not in live_sg_refs
      and uuid.UUID(i["id"]).version == 4)

  print("[replay] Hermes: %s" % ", ".join(
      "%d %s intents, %d stale" % (len(intents[k]), k, len(stale[k]))
      for k in ("security_group", "port_set", "address_set")))
  # Referrers first: a security group references port and address sets.
  for kind in ("security_group", "port_set", "address_set"):
    for intent_id in stale[kind]:
      if dry_run:
        print("  [replay] WOULD delete Hermes %s %s" % (kind, intent_id))
        continue
      status, body = hermes_request(kubectl, atlas_pod, "DELETE",
                                    "v1/%s/%s" % (kind, intent_id))
      if status not in (200, 202, 204, 404):
        raise RuntimeError("Hermes DELETE v1/%s/%s returned %d: %s"
                           % (kind, intent_id, status, body[:200]))
      print("  [replay] deleted Hermes %s %s (%d)" % (kind, intent_id, status))


def wait_for_replay(zk, timeout_secs, interval_secs=30):
  deadline = time.time() + timeout_secs
  while True:
    migration = zk_display(zk_bytes(zk.get(MIGRATION_ZK)))
    status = zk_display(zk_bytes(zk.get(RECOVERY_STATUS_ZK)))
    print("  [replay] migration=%s flow_anc_recovery_status=%s"
          % (migration, status), flush=True)
    if migration == "RECOVERY_COMPLETED" and status == "RECOVERED":
      return
    if time.time() >= deadline:
      raise RuntimeError("replay did not complete within %ds; check the SMSP "
                         "atlas and kratos logs" % timeout_secs)
    time.sleep(interval_secs)


def run_replay(args, kubectl, cpdb):
  """Trigger the SMSP migration recovery, wait for it, clean up PolicyDB."""
  endpoint = resolve_zk_endpoint(args)
  zk = connect_zk(endpoint)
  try:
    print("[replay] current: migration=%s flow_anc_recovery_status=%s "
          "dependency_recovery=%s"
          % tuple(zk_display(zk_bytes(zk.get(p))) for p in
                  (MIGRATION_ZK, RECOVERY_STATUS_ZK, DEPENDENCY_RECOVERY_ZK)))
    if args.dry_run:
      print("[replay] WOULD clear %s and %s, set %s=STARTED, restart %s, wait "
            "for RECOVERY_COMPLETED/RECOVERED"
            % (DEPENDENCY_RECOVERY_ZK, RECOVERY_STATUS_ZK, MIGRATION_ZK,
               "/".join(REPLAY_DEPLOYMENTS)))
      cleanup_policydb(kubectl, cpdb, dry_run=True)
      cleanup_hermes(kubectl, cpdb, dry_run=True)
      return
    # Markers left by an earlier replay would let Kratos start before Atlas
    # has recovered the ports it depends on.
    for path in (DEPENDENCY_RECOVERY_ZK, RECOVERY_STATUS_ZK):
      if zk.get(path) is not None and not zk.delete(path):
        raise RuntimeError("failed to delete ZK node %s: %s"
                           % (path, zk.error()))
    zk_set(zk, MIGRATION_ZK, b"STARTED")
    print("[replay] %s=STARTED; restarting %s"
          % (MIGRATION_ZK, ", ".join(REPLAY_DEPLOYMENTS)))
    for deployment in REPLAY_DEPLOYMENTS:
      kubectl("rollout", "restart", "deployment/%s" % deployment)
    for deployment in REPLAY_DEPLOYMENTS:
      kubectl("rollout", "status", "deployment/%s" % deployment,
              "--timeout=%ds" % args.replay_timeout)
    wait_for_replay(zk, args.replay_timeout)
  finally:
    zk.close()
  print("[replay] recovery complete")
  cleanup_policydb(kubectl, cpdb, dry_run=False)
  cleanup_hermes(kubectl, cpdb, dry_run=False)


# --------------------------------------------------------------------------- #
# Force-retire
# --------------------------------------------------------------------------- #
# The PC-local subset of atlas FlowSmspDeleteTask, for when the SMSP is lost and
# flow_controller.create must run again; every step needing a live SMSP is
# skipped. Side effect: delete_smsp_info_on_pc makes PC IDF garbage-collect all
# SMSP-mastered replicas, so PC is not a recovery source; restore from the tar.
#
# Needs the Atlas venv. Its modules are imported only for this command, so
# backup/restore keep working in venvs without them.

# flow_smsp last: it is the create singleton guard, and unreserve_leaked_vips
# reads the PE/subnet list from it.
RETIRE_RECORDS = [
    "global_network_controller",
    "network_controller",
    "flow_smsp",
]


def import_atlas_modules():
  """Import the Atlas modules force-retire uses; they define gflags, so this
  must run before init_gflags()."""
  try:
    import acropolis.client.remote_client  # noqa: F401
    import atlas.flow_smsp.data_sync.cluster_external_state  # noqa: F401
    import atlas.flow_smsp.flags  # noqa: F401 - smsp_cfs_host/port, cfs flags
    import atlas.flow_smsp.ssl_terminator  # noqa: F401
    import atlas.utils.utils  # noqa: F401
  except ImportError as ex:
    raise SystemExit("force-retire needs the Atlas venv "
                     "(/home/nutanix/.venvs/bin/bin/python3): %s" % ex)


def retire_log(step, msg):
  print("[%s] %s" % (step, msg), flush=True)


def get_flow_smsp_proto(cpdb):
  """FlowSmsp proto from the flow_smsp row's zlib `__zprotobuf__` column."""
  from atlas.atlas_types_pb2 import FlowSmsp
  for entity in cpdb.get_entities_of_type("flow_smsp", metadata_only=False,
                                          include_deleted=False):
    proto = decode_zproto(entity, FlowSmsp)
    if proto is not None:
      return proto
  return None


def unreserve_leaked_vips(cpdb, apply):
  """Release the PE VIP reservations create made under cookie = FC UUID.

  Otherwise the next create fails its free-IP precheck. Must run before
  flow_smsp is deleted. Mirrors delete_task._unreserve_ips_for_smsp_vips.
  """
  from acropolis.acropolis_interface_pb2 import NetworkReserveIpArg
  from acropolis.client.remote_client import RemoteAcropolisClient
  from atlas.common.types import AtlasUuid
  from util.net.protocol.types import IPv4Address

  proto = get_flow_smsp_proto(cpdb)
  if proto is None:
    retire_log("unreserve", "no flow_smsp record; nothing to unreserve")
    return
  # Must match the cookie create used byte-for-byte.
  cookie = AtlasUuid.from_hex(proto.uuid).to_hex()
  pe_list = [pe for pe in proto.smsp_cluster_spec.pe_cluster_details_list
             if pe.ip_count_to_reserve > 0]
  if not pe_list:
    retire_log("unreserve", "no PE entries with ip_count_to_reserve > 0")
    return
  for pe in pe_list:
    desc = ("pe=%s subnet=%s cookie=%s (ip_count_to_reserve=%d)" %
            (pe.pe_cluster_uuid, pe.subnet_uuid, cookie, pe.ip_count_to_reserve))
    if not apply:
      retire_log("unreserve", "WOULD NetworkReserveIp(kUnreserve) %s" % desc)
      continue
    try:
      arg = NetworkReserveIpArg()
      arg.network_uuid = AtlasUuid.from_hex(pe.subnet_uuid).bytes
      arg.operation = NetworkReserveIpArg.kUnreserve
      arg.cookie = cookie
      client = RemoteAcropolisClient(AtlasUuid.from_hex(pe.pe_cluster_uuid))
      ret = client.NetworkReserveIp(arg)
      freed = [str(IPv4Address(ip)) for ip in ret.ip_address_list]
      retire_log("unreserve", "freed %d IP(s) %s -> %s"
                 % (len(freed), desc, freed))
    except Exception as ex:  # noqa: BLE001 - PE may be transiently unreachable
      retire_log("unreserve", "WARN (non-fatal): failed %s -> %s" % (desc, ex))


def delete_retire_records(cpdb, apply):
  for etype in RETIRE_RECORDS:
    entities = cpdb.get_entities_of_type(etype, metadata_only=False,
                                         include_deleted=False)
    if not entities:
      retire_log("idf", "%-28s already absent" % etype)
      continue
    for entity in entities:
      eid = entity.entity_guid.entity_id
      is_cas = entity.HasField("cas_value")
      if not apply:
        retire_log("idf", "%-28s WOULD delete entity_id=%s (cas=%s)" %
                   (etype, eid, entity.cas_value if is_cas else None))
        continue
      # No direct purge: IDF rejects it with kRetry for as long as this
      # entity holds its shard's latest write, which on an idle PC is forever.
      cpdb.delete_entity(entity, is_cas_entity=is_cas)
      retire_log("idf", "%-28s deleted entity_id=%s" % (etype, eid))


def routing_unwire(zk, apply):
  from atlas.flow_smsp.ssl_terminator import (
      retain_flow_cmsp_ssl_terminator_node, update_mercury_config)
  from atlas.utils.consts import LOCAL_ADDRESS
  from atlas.utils.utils import (
      set_atlas_client_zk_node_val, set_flow_client_zk_node_val)

  actions = [
      ("ssl_terminator",
       "retain flow_ssl_terminator websocket-only (stop UI hang)",
       lambda: retain_flow_cmsp_ssl_terminator_node(zk)),
      ("mercury",
       "strip dead-SMSP host from mercury flow config + restart mercury",
       update_mercury_config),
      ("atlas_client_zk",
       "atlas client location -> %s" % LOCAL_ADDRESS,
       lambda: set_atlas_client_zk_node_val(zk, LOCAL_ADDRESS)),
      ("flow_client_zk",
       "flow client host -> %s" % LOCAL_ADDRESS,
       lambda: set_flow_client_zk_node_val(zk, LOCAL_ADDRESS)),
  ]
  for tag, desc, fn in actions:
    if not apply:
      retire_log(tag, "WOULD " + desc)
      continue
    fn()
    retire_log(tag, "done: " + desc)


def cfs_cleanup(smsp_uuid, apply):
  """Unregister the stale CFS "flow" endpoint on PC-local CFS.

  A leftover registration makes the next create fail at _cfs_register_endpoint.
  Inspect: ~/ncc/bin/nusights/pulse_cli print zk_persistent_register_epconfig
  """
  from nusights.util.cfs_config_pb2 import (
      CfsRpcSvc_Stub, UnRegisterEndpointArg)
  from util.net.http_protobuf_rpc import HttpProtobufRpcClient
  from util.net.protobuf_rpc import ProtobufRpc

  host, port = FLAGS.smsp_cfs_host, FLAGS.smsp_cfs_port
  if not apply:
    retire_log("cfs_unregister",
               "WOULD UnRegisterEndpoint(uuid=%s) via %s:%d (tag=%s)"
               % (smsp_uuid, host, port, FLAGS.cfs_registration_endpoint_tag))
    return
  try:
    svc = CfsRpcSvc_Stub(HttpProtobufRpcClient(host, port))
    arg = UnRegisterEndpointArg()
    arg.uuid = smsp_uuid
    done_event = threading.Event()
    resp = {}

    def done(response):
      resp["response"] = response
      done_event.set()

    svc.UnRegisterEndpoint(ProtobufRpc(), arg, done)
    done_event.wait(timeout=FLAGS.cfs_rpc_wait_timeout)
    retire_log("cfs_unregister", "done: UnRegisterEndpoint(uuid=%s) -> %s"
               % (smsp_uuid, resp.get("response")))
  except Exception as ex:  # noqa: BLE001 - PC-local CFS may be down
    retire_log("cfs_unregister", "WARN (non-fatal): %s" % ex)


def zk_cleanup(zk, smsp_uuid, apply):
  """Required whether or not the new SMSP reuses this UUID: it makes PC drop
  the dead SMSP's replicas and sync state so reverse sync restarts clean, and
  with a new UUID nothing else would remove these UUID-keyed nodes."""
  from atlas.flow_smsp.consts import FLOW_CONTROLLER_CFS_RESIZE_CONFIG_ZK_PATH
  from atlas.flow_smsp.data_sync.cluster_external_state import (
      delete_cluster_external_state_node)
  from atlas.utils.utils import (
      delete_smsp_info_on_pc, remove_flow_cfs_resize_config_zk_node)

  steps = [
      ("reverse_sync_zk",
       "delete_smsp_info_on_pc(%s)" % smsp_uuid,
       lambda: delete_smsp_info_on_pc(zk, smsp_uuid)),
      ("cluster_external_state",
       "delete_cluster_external_state_node(%s)" % smsp_uuid,
       lambda: delete_cluster_external_state_node(smsp_uuid, zk)),
      ("cfs_resize_zk",
       "remove_flow_cfs_resize_config_zk_node",
       lambda: remove_flow_cfs_resize_config_zk_node(
           zk, FLOW_CONTROLLER_CFS_RESIZE_CONFIG_ZK_PATH)),
  ]
  for tag, desc, fn in steps:
    if not apply:
      retire_log(tag, "WOULD " + desc)
      continue
    try:
      fn()
      retire_log(tag, "done: " + desc)
    except Exception as ex:  # noqa: BLE001 - best-effort ZK cleanup
      retire_log(tag, "WARN (non-fatal): %s -> %s" % (desc, ex))


def smsp_reachable(smsp_uuid, timeout):
  """(True, detail) if the SMSP's own ZK answers through the iKat tunnel.

  A TCP connect is not enough: the PC-side iKat proxy accepts it locally even
  with nothing behind it. A ZK session needs the real SMSP ZK to respond.
  """
  from zeus.zookeeper_session import ZookeeperSession

  host = IKAT_TUNNEL_PC_ENDPOINT % smsp_uuid
  try:
    socket.gethostbyname(host)
  except socket.gaierror:
    return False, "%s does not resolve" % host
  endpoint = "%s:%d" % (host, DEFAULT_SMSP_ZK_PORT)
  session = ZookeeperSession(host_port_list=endpoint)
  try:
    if session.wait_for_connection(timeout=timeout):
      return True, "ZK session to %s established" % endpoint
    return False, "no ZK session to %s within %ds" % (endpoint, timeout)
  finally:
    session.close()


def cleanup_pc_registration_services(smsp_uuid, apply):
  """Remove the lost SMSP's UUID-named PC iKat routing Services.

  The normal delete task removes the flow-pc-registration svcmgr deployment.
  In a forced retirement, that deployment may already have been reused by a
  replacement SMSP, so deleting it would cut off the replacement.  Delete only
  the two Kubernetes Services rendered for the retired UUID instead.
  """
  names = ["smsp-%s" % smsp_uuid, "cluster-%s" % smsp_uuid]
  if not apply:
    retire_log("pc_registration",
               "WOULD delete Services in %s: %s" %
               (PC_IKAT_NAMESPACE, ", ".join(names)))
    return

  # Facade: keep the UUID-scoped Kubernetes cleanup behind one idempotent
  # force-retire step, rather than exposing the chart's two resource names.
  command = (["sudo", "-n", "kubectl", "-n", PC_IKAT_NAMESPACE, "delete",
              "service"] + names + ["--ignore-not-found"])
  try:
    completed = subprocess.run(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, check=False,
                               text=True)
  except OSError as ex:
    raise SystemExit("[pc_registration] could not run kubectl: %s" % ex)
  if completed.returncode:
    raise SystemExit("[pc_registration] cleanup failed (rc=%d): %s" %
                     (completed.returncode, completed.stdout.strip()))
  retire_log("pc_registration", "deleted or already absent: %s" %
             ", ".join(names))


def cmd_force_retire(args):
  from zeus.zookeeper_session import ZookeeperSession

  mode = "APPLY" if args.apply else "DRY-RUN"
  retire_log("mode", "%s (use --apply to execute)" % mode)
  # PC's own ZK and IDF: this command never talks to the SMSP.
  zk = ZookeeperSession()
  if not zk.wait_for_connection(timeout=30):
    raise SystemExit("could not connect to PC Zookeeper")
  cpdb = connect_cpdb(args.pc_idf_ip, args.pc_idf_port)

  proto = get_flow_smsp_proto(cpdb)
  smsp_uuid = (proto.smsp_cluster_uuid
               if proto is not None and proto.HasField("smsp_cluster_uuid")
               else None)
  retire_log("state", "orphaned smsp_cluster_uuid=%s" % smsp_uuid)
  if smsp_uuid is None:
    retire_log("state", "no flow_smsp record found; nothing to retire")
    return 0

  alive, detail = smsp_reachable(smsp_uuid, args.liveness_timeout)
  retire_log("liveness", "SMSP %s: %s" % ("ALIVE" if alive else "unreachable",
                                          detail))
  if alive:
    if args.apply and not args.force:
      raise SystemExit("[liveness] refusing --apply: SMSP %s still answers, "
                       "and force-retire would cut it off from PC. Pass "
                       "--force only if it is being decommissioned anyway."
                       % smsp_uuid)
    retire_log("liveness", "WARN: --apply will refuse unless --force is given"
               if not args.apply else "WARN: --force given; continuing")

  cleanup_pc_registration_services(smsp_uuid, args.apply)
  routing_unwire(zk, args.apply)
  zk_cleanup(zk, smsp_uuid, args.apply)
  cfs_cleanup(smsp_uuid, args.apply)
  unreserve_leaked_vips(cpdb, args.apply)
  delete_retire_records(cpdb, args.apply)

  retire_log("done", "%s complete" % mode)
  if not args.apply:
    retire_log("done", "re-run with --apply (with atlas stopped) to execute")
  return 0


# --------------------------------------------------------------------------- #
def add_ssh_args(parser, host_help, path_help):
  """Backup-host options; host_help=None when --scp-host is defined elsewhere."""
  if host_help:
    parser.add_argument("--scp-host", default=None, help=host_help)
  parser.add_argument("--scp-user", default="nutanix")
  parser.add_argument("--scp-path", default=DEFAULT_SCP_PATH,
                      help="%s (default: %%(default)s)" % path_help)
  parser.add_argument("--ssh-key", default=DEFAULT_SSH_KEY,
                      help="dedicated private key (default: %(default)s)")
  parser.add_argument("--known-hosts", default=DEFAULT_KNOWN_HOSTS,
                      help="pinned host key of --scp-host "
                           "(default: %(default)s)")


def main():
  parser = argparse.ArgumentParser(
      description="Flow SMSP backup/restore (IDF + ZK)")
  parser.add_argument("--idf-ip", default=None,
                      help="SMSP IDF server IP (default: the SMSP's iKat "
                           "tunnel address, resolved on the PCVM)")
  parser.add_argument("--idf-port", type=int, default=DEFAULT_IDF_PORT,
                      help="IDF server port (default: 2027)")
  parser.add_argument("--smsp-uuid", default=None,
                      help="SMSP cluster uuid (default: discovered with "
                           "mspctl); IDF and Zookeeper are reached at "
                           "%s:{2027,%d}"
                           % (IKAT_TUNNEL_PC_ENDPOINT % "<uuid>",
                              DEFAULT_SMSP_ZK_PORT))
  parser.add_argument("--zk-host-port", default=None,
                      help="explicit SMSP Zookeeper host:port, overriding "
                           "--smsp-uuid (e.g. when running inside the cluster)")
  sub = parser.add_subparsers(dest="cmd", required=True)

  bkp = sub.add_parser("backup",
                       help="dump tables -> tar.gz streamed over ssh")
  bkp.add_argument("--tables", default=None,
                   help="comma-separated IDF entity type names (default: all "
                        "%d SMSP-authored types, i.e. atlas's "
                        "SMSP_MIGRATION_ENTITY_TYPES_LIST)"
                        % len(SMSP_ENTITY_TYPES))
  bkp.add_argument("--out-dir", default=DEFAULT_BACKUP_ROOT,
                   help="local archive directory, used without --scp-host or "
                        "with --keep-local (default: %(default)s)")
  add_ssh_args(bkp, "backup host the archive is streamed to over ssh; omit "
                    "to only write a local archive",
               "remote directory, created if absent")
  bkp.add_argument("--keep-local", action="store_true",
                   help="also keep a copy of the streamed archive in --out-dir")
  bkp.set_defaults(func=run_backup)

  res = sub.add_parser("restore", help="archive -> SMSP ZK + IDF -> replay")
  src = res.add_mutually_exclusive_group(required=True)
  src.add_argument("--in-tar", help="local archive to restore")
  src.add_argument("--scp-host", default=None,
                   help="backup host to stream the archive from over ssh")
  add_ssh_args(res, None, "remote directory holding the archives")
  res.add_argument("--archive", default=None,
                   help="archive name on --scp-host (default: the newest "
                        "flow_backup_*.tar.gz there)")
  res.add_argument("--work-dir", default=None,
                   help="empty directory to extract into (default: a new "
                        "~/flow_br_restore_* directory, kept for inspection)")
  res.add_argument("--dry-run", action="store_true",
                   help="preview only: reports the incarnation each row would "
                        "get and which rows would be skipped, without writing")
  res.add_argument("--no-flush", action="store_true",
                   help="do NOT delete existing target rows first (merge "
                        "instead of replace); default is to flush each table")
  res.add_argument("--tables", default=None,
                   help="comma-separated subset of tables to restore "
                        "(default: every .b64 in the tar)")
  res.add_argument("--non-cas", action="store_true",
                   help="write rows as non-CAS (local-only, will NOT reverse-"
                        "sync to PC); default writes CAS entities")
  res.add_argument("--replica-idf-ip", default="127.0.0.1",
                   help="IDF of the replica (PC) to read current incarnation "
                        "ids and entity ownership from (default: local PC)")
  res.add_argument("--replica-idf-port", type=int, default=DEFAULT_IDF_PORT,
                   help="replica IDF port (default: 2027)")
  res.add_argument("--restore-replay-minted", action="store_true",
                   help="also write back the tables the replay mints fresh "
                        "uuids for (%s); default skips them. Use this to "
                        "reproduce the orphaned-row gap on purpose."
                        % ", ".join(REPLAY_MINTED_TABLES))
  res.add_argument("--zk-paths", default=None,
                   help="comma-separated ZK paths to write back (default: the "
                        "%d values the rebuilt SMSP cannot re-derive, %s). "
                        "Widening this can overwrite service-owned state such "
                        "as leader election or migration status."
                        % (len(ZK_RESTORE_PATHS), ", ".join(ZK_RESTORE_PATHS)))
  res.add_argument("--owner-uuids", default=None,
                   help="comma-separated cluster uuids the SMSP may write on "
                        "behalf of. Rows the replica masters under any other "
                        "cluster are skipped, so a restore cannot steal "
                        "PE-owned entities. Default: the backed-up SMSP uuid "
                        "from the archive manifest plus the rebuilt SMSP uuid "
                        "(--smsp-uuid or mspctl); these are equal when the "
                        "uuid was reused.")
  res.add_argument("--skip-replay", action="store_true",
                   help="only restore ZK + IDF; do not trigger the SMSP "
                        "recovery replay (needed when not on a PCVM)")
  res.add_argument("--replay-timeout", type=int, default=45 * 60,
                   help="seconds to wait for the pod restarts and for the "
                        "replay to complete (default: %(default)s)")
  res.add_argument("--allow-version-mismatch", action="store_true",
                   help="restore an archive taken on a different PC release "
                        "(major.minor) than the one running")
  res.set_defaults(func=cmd_restore)

  ret = sub.add_parser("force-retire",
                       help="after the SMSP is lost: clear the orphaned Flow "
                            "Controller on PC so flow_controller.create can "
                            "run again (run with atlas stopped)")
  ret.add_argument("--apply", action="store_true",
                   help="execute; default is a dry-run that prints the "
                        "intended actions")
  ret.add_argument("--force", action="store_true",
                   help="apply even if the SMSP still answers over iKat")
  ret.add_argument("--liveness-timeout", type=int, default=30,
                   help="seconds to wait for the SMSP's ZK over iKat before "
                        "treating it as lost (default: %(default)s)")
  ret.add_argument("--pc-idf-ip", default="127.0.0.1",
                   help="PC IDF (default: %(default)s)")
  ret.add_argument("--pc-idf-port", type=int, default=DEFAULT_IDF_PORT)
  ret.set_defaults(func=cmd_force_retire)

  zst = sub.add_parser("zk-status", help="print the backup status in PC ZK")
  zst.set_defaults(func=cmd_zk_status)
  zin = sub.add_parser("zk-init",
                       help="create/enable the PC ZK status node (install.sh)")
  zin.add_argument("--backup-node-ip", required=True,
                   help="PCVM IP whose timer runs the backups")
  zin.add_argument("--interval-secs", type=int, required=True)
  zin.add_argument("--install-path", required=True,
                   help="directory holding flow-br on every PCVM")
  zin.set_defaults(func=cmd_zk_init)
  zdi = sub.add_parser("zk-disable",
                       help="mark backups disabled (atlas stops re-arming "
                            "the timer and alerts NotEnabled)")
  zdi.set_defaults(func=cmd_zk_disable)
  zsk = sub.add_parser("zk-skip", help="record a skipped backup")
  zsk.add_argument("--reason", required=True)
  zsk.set_defaults(func=cmd_zk_skip)
  zti = sub.add_parser("zk-timer", help="write this PCVM's timer heartbeat")
  zti.add_argument("--node-ip", required=True)
  zti.add_argument("--healthy", action="store_true")
  zti.add_argument("--next-fire-usecs", type=int, default=0)
  zti.add_argument("--detail", default="")
  zti.set_defaults(func=cmd_zk_timer)

  args = parser.parse_args()
  if args.cmd == "force-retire":
    import_atlas_modules()
  init_gflags()
  # force-retire works on PC state only; the SMSP is gone, so don't discover
  # it. backup discovers it itself so the failure is recorded in PC ZK.
  if args.cmd == "restore":
    ensure_idf_ikat(args)
    resolve_smsp_endpoints(args)
  return args.func(args)


if __name__ == "__main__":
  sys.exit(main())

# Flow Controller Backup and Restore

Field guide and design for the Flow SMSP (Flow Controller) backup and restore package.

**Important.** Use this tool only under the guidance of Nutanix Support or an authorized partner. It is a script-based field package, not a productized feature. Validate it against the target Prism Central and Flow versions before use. The package is distributed as a tarball from either a direct Portal URL or an internal URL, so that it is used under SRE/DevEx guidance. See *Get the package* below.

## Contents

1. What this offers
2. Package contents
3. Prerequisites
4. Install
5. Day-to-day operation
6. Disaster recovery runbook
7. Command reference
8. Design
9. Scheduling, upgrades, and resilience
10. Security model
11. Limitations and caveats
12. Troubleshooting

## 1. What this offers

The Flow Controller runs on a dedicated Service MSP (SMSP) cluster that Prism Central (PC) manages. The SMSP owns the authoritative copy of Flow networking and security configuration (VPCs, subnets, ports, security policies, address and service groups, and related objects) in its own IDF and Zookeeper (ZK).

If the SMSP is lost, PC alone cannot rebuild that configuration. When the dead Flow Controller is removed from PC, PC garbage-collects its replicas of SMSP-mastered data. This package keeps an off-PC copy of the SMSP state and can rebuild a replacement SMSP from it.

**Capabilities**

- **Scheduled backup.** A systemd timer on the PCVM snapshots SMSP IDF (53 Flow entity types) and the relevant SMSP ZK subtrees into one tar.gz archive, streamed over SSH to an external backup host. Archives are checksum-verified, published atomically, and pruned by retain count.
- **Force-retire.** After the SMSP is lost, clears the orphaned Flow Controller state on PC so a new Flow Controller can be created through the normal product workflow.
- **Restore.** Fetches and verifies an archive, writes the small set of irreplaceable ZK values, re-attaches IDF rows into the new SMSP, and triggers Flow’s own SMSP migration-recovery replay. The replay reprograms the data plane (ANC / PolicyDB).

**Out of scope.** This package does not back up Prism Central itself, Prism Element, VM data, or the SMSP’s Kubernetes / MSP infrastructure. Recovery is a manual, operator-gated procedure, not automatic failover.

## 2. Package contents

**Files in the tarball**

| File | Purpose |
| --- | --- |
| install.sh | One-time interactive setup on the PCVM (config, SSH key, pinned host key, test backup, timer). |
| flow-br | Operator CLI. Reads flow_br.conf and wraps the Python engine. |
| flow_br_poc.py | Engine (Atlas venv). Implements backup, restore with replay, and force-retire. |
| flow_br.conf.example | Annotated config template. |
| systemd/flow-br-backup.service | Oneshot unit that runs flow-br backup. |
| systemd/flow-br-backup.timer | Schedule template. OnCalendar and delay are filled in by the installer. |

**Installed layout on the PCVM**

Everything under /home survives a PC upgrade. Units under /etc are lost on upgrade and must be re-registered with flow-br ensure-timer.

```text
/home/nutanix/flow_br/
  flow-br, flow_br_poc.py, flow_br.conf, flow_br.conf.example
  known_hosts                 # pinned backup-host key
  systemd/                    # rendered units (source for ensure-timer)
  logs/backup-*.log
  backup.lock

/home/nutanix/.ssh/flow_br_backup     # dedicated RSA-4096 private key
/home/nutanix/.ssh/flow_br_backup.pub

/etc/systemd/system/flow-br-backup.service   # lost on PC upgrade
/etc/systemd/system/flow-br-backup.timer     # lost on PC upgrade
```

## 3. Prerequisites

**On the PCVM**

- Prism Central with Flow Controller deployed on an SMSP and registered with this PC.
- Shell as the nutanix user (for example: log in as admin, then choose NuService menu option 3).
- Passwordless sudo, required to install the systemd units.
- Atlas venv Python at /home/nutanix/.venvs/bin/bin/python3.
- mspctl at /usr/local/nutanix/cluster/bin/mspctl (SMSP discovery and kubeconfig).

**On the backup host**

- Any Linux host reachable over SSH from the PCVM.
- Enough disk for (retain count × archive size). Archives are small; about 170 KB for roughly 560 entities in testing.
- An account where you can append the PCVM’s public key to authorized_keys.
- An ECDSA host key at /etc/ssh/ssh_host_ecdsa_key.pub. The PCVM runs in FIPS mode and cannot use ssh-keyscan, so the host key is pinned by hand.

## 4. Install

### 4.1 Get the package

The package is distributed as a single tarball named flow_br_field-\<version\>.tar.gz, with a matching .sha256 checksum file next to it.

**Distribution options**

| Option | Audience | Notes |
| --- | --- | --- |
| Portal (direct URL) | Customers and partners, when published | \<PORTAL_URL\>/flow_br_field-\<version\>.tar.gz |
| Internal only | SRE / DevEx | Shared with a customer during a guided engagement. \<INTERNAL_URL\>/flow_br_field-\<version\>.tar.gz |

**Hosting decision.** The package can be hosted on a direct Portal URL, or kept internal-only if it should be used only under SRE/DevEx guidance. Until that is decided, treat the package as internal-only: do not share the URL publicly, and run it only with SRE/DevEx guidance.

**Download on a PCVM that can reach the URL**

```bash
cd /home/nutanix
curl -fLO <URL>/flow_br_field-<version>.tar.gz
curl -fLO <URL>/flow_br_field-<version>.tar.gz.sha256
sha256sum -c flow_br_field-<version>.tar.gz.sha256
tar -xzf flow_br_field-<version>.tar.gz
cd flow_br_field
```

**Download when the PCVM has no internet access**

1. Download both files on a workstation.
2. Copy them to the PCVM:

```bash
scp flow_br_field-<version>.tar.gz* nutanix@<PCVM_IP>:/home/nutanix/
```

3. On the PCVM, run the same sha256sum and tar commands shown above.

The unpacked directory contains the files listed in section 2. You only need it for installing; install.sh copies everything it needs into /home/nutanix/flow_br. To upgrade the package later, unpack the new version and re-run install.sh.

### 4.2 Run the installer

From the unpacked directory:

```bash
./install.sh
```

**Installer prompts**

| Prompt | Example / default |
| --- | --- |
| Backup host | 10.0.0.50 or DNS name |
| Backup SSH user | nutanix |
| Remote backup directory | ~/flow_backups |
| Schedule type | 1 = every N hours; 2 = daily at HH:MM UTC |
| Every N hours / daily time | 6 / 02:30 |
| Random delay seconds | 300 (hourly) / 900 (daily) |
| Retain newest N archives | About 7 days’ worth (minimum 14); 0 = keep all |
| Python | /home/nutanix/.venvs/bin/bin/python3 |

**What the installer does**

1. Copies scripts to /home/nutanix/flow_br, writes flow_br.conf (mode 600), and links ~/bin/flow-br.
2. Generates ~/.ssh/flow_br_backup (RSA-4096, FIPS-safe) and prints the public key. Append that key to authorized_keys on the backup host, then press Enter.
3. Asks you to paste the backup host’s pinned key line. On the backup host, run:

```bash
awk -v h=<BACKUP_HOST> '{print h, $1, $2}' /etc/ssh/ssh_host_ecdsa_key.pub
```

4. Optionally runs a test backup: flow-br backup --now.
5. Optionally installs and enables the timer through flow-br ensure-timer (requires passwordless sudo).

**Verify**

```bash
flow-br status
systemctl list-timers flow-br-backup.timer
```

## 5. Day-to-day operation

| Task | Command |
| --- | --- |
| Show config, timer health, newest remote archives | flow-br status |
| Back up now (bypasses scheduled-run prechecks) | flow-br backup --now |
| Re-install / enable the timer after every PC upgrade | flow-br ensure-timer |
| View backup logs | ls -t /home/nutanix/flow_br/logs/ |
| View systemd journal for the backup unit | journalctl -u flow-br-backup.service |
| Change schedule or backup host | Edit flow_br.conf, then re-run install.sh |

**After every PC upgrade.** The upgrade replaces the root filesystem, which removes the units in /etc/systemd/system. flow-br status prints a WARNING when that happens. Run flow-br ensure-timer to restore them. See section 9.

## 6. Disaster recovery runbook

Use this when the Flow SMSP is permanently lost (cluster destroyed or unrecoverable). Every destructive step has a dry-run first.

**Recovery flow**

```text
1.  Confirm SMSP is lost
2.  genesis stop atlas
3.  flow-br cleanup                 # dry-run
4.  flow-br cleanup --apply         # clear orphaned Flow Controller on PC
5.  cluster start
6.  Create replacement Flow Controller (normal product workflow)
7.  Wait until SMSP is healthy (IDF :2027 reachable via iKat)
8.  flow-br restore --dry-run
9.  flow-br restore                 # ZK + IDF + replay + cleanup
10. Verify policies, VPCs, ports
11. flow-br backup --now            # fresh baseline
```

**Step details**

1. **Confirm the SMSP is lost.** Force-retire also checks liveness itself (see section 8.4).
2. **genesis stop atlas.** Atlas must be stopped while PC state is cleared.
3. **flow-br cleanup.** Dry-run of force-retire. Prints every action it would take.
4. **flow-br cleanup --apply.** Asks for confirmation. Refuses if the SMSP still answers. Override with --force only if you are decommissioning it.
5. **cluster start.** Brings Atlas back.
6. **Create the replacement Flow Controller.** Use the normal UI or API workflow. It may get a new SMSP UUID.
7. **Wait for SMSP health.** Restore needs SMSP IDF and ZK reachable over the iKat tunnel.
8. **flow-br restore --dry-run.** Shows ZK writes, per-row attach and incarnation, flushes, and replay or cleanup intentions. No writes.
9. **flow-br restore.** Asks for confirmation. Restores ZK and IDF, triggers replay, waits up to 45 minutes, and cleans up stale data-plane objects.
10. **Verify.** Use the PC UI and flow_cli to check policies, VPCs, subnets, ports, and data-path behaviour.
11. **flow-br backup --now.** Take a fresh baseline from the rebuilt SMSP.

To restore a specific archive instead of the newest:

```bash
flow-br restore --archive flow_backup_<uuid>_<YYYYMMDDTHHMMSSZ>.tar.gz
```

On the PCVM, flow-br recover-help prints this sequence.

## 7. Command reference

### 7.1 flow-br (operator CLI)

```text
flow-br status
flow-br backup [--now]
flow-br cleanup [--apply] [--force]
flow-br restore [--dry-run] [--archive NAME] [extra engine flags]
flow-br ensure-timer [--quiet]
flow-br recover-help
```

- **backup.** Takes a flock on backup.lock so manual and scheduled runs never overlap. Writes output to logs/backup-\<UTC\>.log. On success, prunes the backup host to BACKUP_RETAIN_COUNT archives (and their .sha256 files). --now means a manual run and skips the scheduled-run prechecks.
- **restore.** Passes any extra arguments through to the engine (for example --tables, --no-flush, --replay-timeout).

### 7.2 flow_br.conf

| Key | Meaning |
| --- | --- |
| BACKUP_HOST, BACKUP_USER, BACKUP_PATH | Destination. ~ expands on the remote side. |
| SSH_KEY, KNOWN_HOSTS | Dedicated key and pinned host key. |
| PYTHON, FLOW_BR_SCRIPT | Atlas venv interpreter and engine path. |
| BACKUP_ONCALENDAR | systemd OnCalendar value (for example hourly, \*-\*-\* 0/6:00:00, \*-\*-\* 02:30:00). |
| BACKUP_RANDOMIZED_DELAY_SEC | Jitter added to each timer fire. |
| BACKUP_RETAIN_COUNT | Newest N archives kept remotely. 0 keeps all. |
| BACKUP_LEADER_CHECK | 1 = on scale-out PC, only the lowest-IP PCVM (from svmips) runs scheduled backups. |
| BACKUP_REQUIRE_CLUSTER_UP | 1 = scheduled run skips with exit 0 if insights_server is not running. |

### 7.3 flow_br_poc.py (engine)

Global flags go before the subcommand.

| Global flag | Default |
| --- | --- |
| --smsp-uuid | Discovered via mspctl cluster list (the service_msp named flow). |
| --idf-ip / --idf-port | Resolved from smsp-\<uuid\>.ntnx-ikat.svc / 2027. |
| --zk-host-port | smsp-\<uuid\>.ntnx-ikat.svc:9876. Never defaults to PC’s own ZK. |

**backup flags:** --tables, --out-dir, --scp-host, --scp-user, --scp-path, --ssh-key, --known-hosts, --keep-local.

**restore flags**

| Flag | Effect |
| --- | --- |
| --scp-host or --in-tar | Source: remote stream, or a local file. |
| --archive | Specific remote archive. Default is the newest. |
| --work-dir | Must be empty. Default is a new ~/flow_br_restore_\* directory, kept for inspection. |
| --dry-run | Preview only. No writes. |
| --no-flush | Merge into existing rows instead of replacing them. |
| --tables | Restore a subset of tables only. |
| --non-cas | Write non-CAS rows. They will not reverse-sync to PC. |
| --replica-idf-ip / --replica-idf-port | PC IDF used for incarnation and ownership reads. Default 127.0.0.1:2027. |
| --owner-uuids | Override the owning-cluster set. Default is the backed-up and rebuilt SMSP UUIDs. |
| --zk-paths | Override the ZK allow-list. Dangerous; see section 8.3. |
| --restore-replay-minted | Also write the replay-minted tables. For reproducing a known gap only. |
| --skip-replay | Restore IDF and ZK only. Replay by hand. |
| --replay-timeout | Seconds to wait. Default 2700. |

**force-retire flags:** --apply, --force, --liveness-timeout (default 30 seconds), --pc-idf-ip, --pc-idf-port.

## 8. Design

### 8.1 Architecture

The package runs entirely on the PCVM. Nothing is installed on the SMSP. The SMSP’s IDF and ZK are reached through the PC-side iKat tunnel. The backup host is reached over SSH with a dedicated key and a pinned host key.

```text
PCVM
  systemd timer --> flow-br backup --> flow_br_poc.py
                                         |
                    +--------------------+--------------------+
                    |                    |                    |
                 mspctl              PC IDF :2027          SSH
              (discover SMSP)     (replica; restore)   (dedicated key)
                    |                    |                    |
                    v                    v                    v
              Flow SMSP             (read-only)         Backup host
           via iKat tunnel                           ~/flow_backups/
             IDF  :2027                              *.tar.gz + *.sha256
             ZK   :9876
             atlas / kratos / ANC
             (kubectl; restore only)
```

**Key design choices**

- **Runs on PC, talks to the SMSP over iKat.** The SMSP’s IDF and ZK are reached at smsp-\<uuid\>.ntnx-ikat.svc.
- **Never confuses PC ZK with SMSP ZK.** Both hold the same paths with different values, so the ZK endpoint is always explicit. There is no local default.
- **Streaming, no staging.** Backup streams tar.gz straight into ssh cat. Restore streams ssh cat straight into the tar extractor. Only the largest single table is ever held in memory.
- **Reuse product mechanisms.** Re-programming ANC and PolicyDB is left to Flow’s own CMSP-to-SMSP migration-recovery path. The script only sets up its preconditions and cleans up leftovers.

### 8.2 Backup

**Sequence**

1. flow-br runs prechecks (designated node, cluster up) and takes a flock.
2. flow_br_poc.py opens an SSH session and starts writing NAME.part on the backup host.
3. For each of 53 entity types: bounded ID query on SMSP IDF, then GetEntities in batches of 500. Each table is streamed into the tar.gz as TABLE.b64. SHA-256 is computed on the fly.
4. Dump four ZK subtrees into smsp_zk_nodes.json. Write backup_manifest.json.
5. On the remote side: verify the SHA-256 of NAME.part, rename it to NAME, and write NAME.sha256.
6. flow-br prunes the remote directory to the newest BACKUP_RETAIN_COUNT archives.

**What is captured**

- **SMSP IDF.** Every row of the 53 SMSP-authored types (mirrors Atlas SMSP_MIGRATION_ENTITY_TYPES_LIST): VPCs, subnets, ports, floating IPs, route tables, gateways, VPN, BGP, security policies and rules, address / service / entity groups, security groups, port sets, QoS, SPAN, IPFIX, and related objects. Each row is a base64-encoded serialized Entity protobuf, one per line, in TABLE.b64.
- **SMSP ZK.** Full snapshots of /appliance/logical/flow, microseg, atlas, and flow_smsp in smsp_zk_nodes.json. Base64 values are authoritative; text is for humans.
- **Manifest.** backup_manifest.json holds format version, archive name, UTC timestamp, SMSP UUID, endpoints, PC hostname, per-table counts, and ZK node count.

**Archive name.** flow_backup_\<smsp_uuid\>_\<YYYYMMDDTHHMMSSZ\>.tar.gz, with a sibling .sha256 file.

**Correctness properties**

- **Bounded reads.** Some types are evictable, and IDF rejects unbounded scans of them. Every table is read as a bounded ID query, then GetEntities in batches.
- **No partial archives.** Any read error aborts the run. The remote .part file is deleted, and nothing is published.
- **Atomic publish.** The remote side verifies the SHA-256 of .part before renaming it, so readers only ever see complete, verified archives.
- **Required ZK guard.** The backup fails if the two scope UUIDs (see below) are missing. Without them, a restore cannot keep port-set UUIDs stable.

### 8.3 Restore

**Pipeline**

1. Fetch the newest or selected archive over SSH.
2. Stream-extract into an empty work directory (flat regular files only).
3. Verify that the in-flight SHA-256 matches NAME.sha256. On mismatch, abort with nothing written.
4. Resolve owner UUIDs (backed-up SMSP plus rebuilt SMSP).
5. Write the four allow-listed ZK values.
6. Per table: flush local rows, then attach backup rows.
7. Flush replay-minted tables (no attach).
8. Replay: set migration=STARTED, restart atlas and kratos, wait for RECOVERY_COMPLETED / RECOVERED.
9. Clean orphan PolicyDB CT_Mapping rows.
10. Clean stale Hermes intents.

**Step 1: fetch and verify.** The archive is streamed from the backup host and hashed in flight. The hash must match NAME.sha256. Extraction accepts only flat regular files, so a damaged or hostile archive cannot write outside the work directory. The work directory must be empty, because every .b64 file in it is restored.

**Step 2: ZK (before IDF and replay).** Only four values are written back. These are values a rebuilt SMSP cannot re-derive.

| ZK path | Why it is restored |
| --- | --- |
| /appliance/logical/flow/global_unique_uuid | Scope UUID. Namespace for uuid5() port-set IDs. |
| /appliance/logical/flow/vlan_unique_uuid | Scope UUID. Same purpose. |
| /appliance/logical/flow/default_policies/strict_quarantine_policy_uuid | Must match the restored default policy rows. |
| /appliance/logical/flow/default_policies/forensic_quarantine_policy_uuid | Must match the restored default policy rows. |

Everything else in the snapshot (leader election, migration state, atlas_config) belongs to live services and is rewritten by create or recovery, so it is deliberately not restored. This must happen before replay: once replay derives port-set UUIDs from the fresh namespace, changing the scope UUIDs would orphan them.

**Step 3: IDF attach (per table)**

- **Flush first (default).** Delete the fresh SMSP’s rows in that table so the result equals the backup, not a merge. --no-flush merges instead.
- **Incarnation.** IDF requires a strictly increasing incarnation_id, and the PC replica drops rows with a lower one. Each row is attached with incarnation = max(backup, PC replica including tombstones) + 1. Reading the replica also makes re-running a restore safe.
- **Ownership protection.** The PC replica reports which cluster masters each row. Rows mastered by a cluster outside {backed-up SMSP, rebuilt SMSP} (for example a PE) are skipped on both flush and attach, so a restore cannot steal them.
- **Writable columns only.** Nested-field-derived attributes are computed by IDF and are filtered out.
- **CAS mode.** Rows are written as CAS so they reverse-sync to PC. If a local row exists in the other CAS mode, it is deleted first.

**Replay-minted tables.** atlas_security_group, flex_security_group, and security_group are backed up for diffing, but on restore they are only flushed, never attached. Replay mints fresh UUIDs for them, so restored rows would only be orphans. atlas_port_set and atlas_port_set_address_set_map are restored, because their UUIDs are uuid5(scope uuid, category) and stay stable once the scope UUIDs are restored.

**Step 4: replay (data-plane reprogramming).** Restoring IDF does not program ANC or PolicyDB. The script reuses Flow’s CMSP-to-SMSP migration recovery:

1. Delete the stale markers for dependency recovery and ANC recovery status.
2. Set /appliance/logical/flow_smsp/migration = STARTED.
3. Restart the atlas and kratos deployments in namespace ntnx-flow (both read migration only at start), using a kubeconfig from mspctl cluster kubeconfig flow.
4. Atlas SmspRecoveryManager replays subnets, VPCs, and ports into ANC and marks dependency recovery done. Kratos then replays address and entity groups and policies and sets the status to RECOVERED. Atlas sets migration = RECOVERY_COMPLETED.
5. The script polls every 30 seconds until both are reached (default timeout 45 minutes).

**Step 5: post-replay cleanup.** Before the restore, the fresh SMSP programmed its own default quarantine policies into the data plane. Restore flushes their IDF rows, but replay only adds, so leftovers are swept:

- **PolicyDB.** Delete CT_Mapping rows in anc-policydb-0 whose nsp_uuid is not in SMSP IDF network_security_policy.
- **Hermes (ANC intent API).** From the atlas pod, list security_group, port_set, and address_set intents, and delete those that IDF does not account for, referrers first. Address sets are only deleted if they are random (uuid4, port-set-generated), not mapped by a live port set, and not referenced by a live security group. AG/EG address sets (uuid5) are never touched.

These are the same delete operations Flow itself performs.

### 8.4 Force-retire

This is the PC-local subset of Atlas FlowSmspDeleteTask, for when the SMSP is gone and flow_controller.create must be able to run again. It works on PC’s own ZK and IDF only.

1. **Identify.** Read smsp_cluster_uuid from PC IDF flow_smsp.
2. **Liveness gate.** Attempt a real ZK session to the SMSP over iKat. A TCP connect is not enough, because the PC-side proxy accepts it locally. If the SMSP is alive, --apply refuses unless --force is given.
3. **PC registration.** Delete the Kubernetes Services smsp-\<uuid\> and cluster-\<uuid\> in namespace ntnx-ikat. The shared svcmgr deployment is left alone, because a replacement may already use it.
4. **Routing unwire.** Set the SSL terminator to websocket-only (stops UI hangs), strip the dead host from the mercury config and restart mercury, and point the atlas and flow client ZK locations back to local.
5. **ZK cleanup.** Remove reverse-sync state (which also makes PC IDF garbage-collect the SMSP-mastered replicas), the cluster external state node, and the CFS resize config.
6. **CFS.** Unregister the endpoint for the SMSP UUID. Otherwise the next create fails at endpoint registration.
7. **VIPs.** Unreserve PE subnet IPs held under the Flow Controller cookie. Otherwise the next create fails its free-IP precheck. This runs before flow_smsp is deleted, because it reads from that record.
8. **IDF records.** Purge global_network_controller, network_controller, and finally flow_smsp (the create singleton guard).

Every step prints WOULD … in dry-run. Steps 5–7 are best-effort (warnings, not failures).

**Consequence.** After step 5, PC no longer holds the SMSP’s data. The backup archive is the only recovery source. Confirm that a recent, verified archive exists before running flow-br cleanup --apply.

## 9. Scheduling, upgrades, and resilience

| Event | Behaviour |
| --- | --- |
| PCVM reboot | The timer is enabled under timers.target and comes back automatically. Persistent=true runs one catch-up backup if a fire was missed while down. |
| cluster stop / start | Does not affect systemd. A scheduled run while services are down logs SKIP and exits 0, so the unit is not marked failed. |
| PC upgrade | Root filesystem is replaced, so /etc/systemd/system/flow-br-\* is lost. Everything under /home/nutanix survives. Run flow-br ensure-timer after the upgrade. flow-br status warns until you do. |
| Scale-out PC (3 nodes) | Only the PCVM with the lowest IP in svmips runs scheduled backups. Others log SKIP. If that node is down, scheduled backups pause until it returns. |
| Overlap | flock on backup.lock prevents concurrent manual and scheduled runs. |

**Design notes**

- Units are system units under /etc/systemd/system, run as nutanix. User units were rejected because they depend on linger state, which a PC upgrade can drop.
- The timer has no Requires= on the service, and the service has no [Install] section. Enabling or starting the timer never triggers an immediate backup, and the service can never be enabled to run at boot.
- ensure-timer is idempotent. It copies units only if missing or changed, reloads only on change, and enables only if not healthy.
- The service runs ExecStart=/bin/bash /home/nutanix/flow_br/flow-br backup because SELinux (Enforcing on PCVM) blocks systemd from executing user_home_t files directly. It runs at Nice=10 with best-effort I/O priority 7.

## 10. Security model

- **Dedicated key.** RSA-4096 at ~/.ssh/flow_br_backup, mode 600, FIPS-compatible, used only for this purpose (IdentitiesOnly=yes).
- **Pinned host key.** StrictHostKeyChecking=yes against a hand-pinned known_hosts file. There is no trust-on-first-use. ssh-keyscan is unusable under PCVM FIPS.
- **Isolated SSH config.** -F /dev/null keeps the PCVM’s own SSH config (control masters, cluster keys) out of the picture. BatchMode=yes means there are never interactive prompts.
- **Integrity.** SHA-256 is computed on the fly on both upload and download, and verified before publish and before any restore write.
- **Safe extraction.** Only flat regular files are accepted. Anything else aborts.
- **File modes.** flow_br.conf and known_hosts are 600. The flow_br directory is 700.
- **Archives are not encrypted.** They contain the full Flow configuration. Restrict access on the backup host (dedicated account, directory permissions, disk encryption if required).

## 11. Limitations and caveats

- Field tool, operator-driven. It needs Nutanix Support or partner guidance and must be re-validated for each PC / Flow version. The entity type list is kept in sync with Atlas by hand.
- Expect a single Flow SMSP per PC. Discovery fails if it finds more than one; pass --smsp-uuid in that case.
- The restore point is the last successful backup. Changes made after it are lost.
- The restore reprograms the data plane through replay, which restarts the SMSP atlas and kratos pods. Expect a Flow control-plane disruption window (up to the replay timeout).
- Bash shell access on PCVMs is planned to be disabled by default in a future release (see KB-20212), which will affect this script-based approach.
- On scale-out PC, the designated backup node is a single point of failure for scheduled backups.

## 12. Troubleshooting

**Timer missing after upgrade**

Symptom: WARNING that flow-br-backup.timer is missing, disabled, or inactive.

Action: Run flow-br ensure-timer.

**ensure-timer cannot write units**

Symptom: needs passwordless sudo.

Action: Run as nutanix with sudo rights.

**SKIP: not the designated backup node**

Expected on non-leader scale-out PCVMs.

Action: Use flow-br backup --now to force a backup on that node.

**SKIP: cluster services not up**

insights_server is down.

Action: Check genesis status and cluster status.

**Another backup is already running**

A run is in progress, or a stale lock holder exists.

Action: Check with pgrep -f flow_br_poc.

**Pinned host key missing or host key verification failed**

Action: On the backup host, run the awk one-liner from section 4.2, then update known_hosts on the PCVM.

**Permission denied (publickey)**

The public key is not in the backup host’s authorized_keys, or it is in the wrong account.

**Expected exactly one Flow SMSP**

Multiple or zero SMSPs.

Action: Pass --smsp-uuid. List clusters with mspctl cluster list.

**Cannot resolve smsp-\<uuid\>.ntnx-ikat.svc**

The SMSP is not registered, or iKat is down.

**ZK snapshot is missing global_unique_uuid**

SMSP ZK is incomplete.

Action: Do not trust this SMSP’s state. Investigate before backing up.

**Checksum mismatch on restore**

The archive is corrupted at rest.

Action: Choose another with --archive.

**Replay did not complete within the timeout**

Action: Check SMSP atlas and kratos logs:

```bash
kubectl -n ntnx-flow logs deploy/atlas
kubectl -n ntnx-flow logs deploy/kratos
```

Re-running the restore is safe (incarnation logic).

**Refusing --apply: SMSP still answers**

The SMSP is alive. Force-retire would cut it off.

Action: Use --force only if you are decommissioning it.

**Where to find logs**

- Backup logs: /home/nutanix/flow_br/logs/backup-\<UTC\>.log
- systemd journal: journalctl -u flow-br-backup.service
- Restore work directory (kept for inspection): ~/flow_br_restore_\*

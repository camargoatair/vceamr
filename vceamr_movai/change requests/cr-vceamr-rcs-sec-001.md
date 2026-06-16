# Change Request — SSH Cryptographic Hardening (MovAI Robot and Manager)

| Field | Value |
|---|---|
| **CR ID** | CR-VCEAMR-RCS-SEC-001 |
| **Title** | SSH server hardening — remove SHA-1 algorithms (vuln 38909) + ECDSA/PQ tightening |
| **Document** | VCEAMR-RCS-CR-SSH-Hardening-Rev01 |
| **Author** | VCE AMR Core Team |
| **Date raised** | 2026-06-16 |
| **Change type** | Standard security change |
| **Risk class** | Medium (remote-access loss if misapplied; fully reversible) |
| **Affected systems** | VCE AMR IPCs (production) and Robot Control System  - MovAI Manager instances — see §2 |
| **Approver** | Atair Camargo |
| **Verifier** | Bruno Oliveira |
| **Status** | Draft — for review |

---

## 1. Purpose & Background

Corporate vulnerability scanning flagged finding **38909 — "SHA1 deprecated setting for SSH"** on MovAI hosts. The SSH daemon was running on OpenSSH compiled-in defaults, which still offer SHA-1-based key-exchange (`diffie-hellman-group14-sha1`, `…group-exchange-sha1`), the SHA-1 MAC (`hmac-sha1`/`-etm`), and RSA-SHA1 host-key signatures (`ssh-rsa`). SHA-1 is broken against collision attack and is non-compliant with the cryptographic baselines underpinning NIS2 / CRA obligations for the program.

This change pins a strong, explicitly-defined algorithm set via a single `sshd_config.d` drop-in, removing all SHA-1 dependence. It additionally:

- drops `ecdsa-sha2-nistp256` (NIST P-256) in favour of `ssh-ed25519` + `rsa-sha2-*`;
- where the OpenSSH build supports it (≥ 8.5), prepends the post-quantum hybrid KEX `sntrup761x25519-sha512@openssh.com` for harvest-now-decrypt-later protection.

The change was developed and validated on a MovAI dev VM (Jammy, OpenSSH 8.9p1); `ssh-audit` returns no `[fail]`/`[warn]` findings post-change. This CR governs controlled rollout to the production fleet.

## 2. Scope & Affected Systems

In scope: the Ubuntu host SSH daemon (`/etc/ssh/sshd_config`) on the following platform classes.

| Class | Platform | OpenSSH | KEX variant |
|---|---|---|---|
| Production AMR IPC | Ubuntu 20.04  | **8.2p1** | **Variant B** (no sntrup761) |
| MovAI dev / staging VM | Ubuntu 22.04 (Jammy) | **8.9p1** | **Variant A** (with sntrup761) |

Out of scope:

- **Container-internal sshd** (if any). This CR targets the *host* daemon. If a scan flags an SSH service running inside a MovAI container, the fix must be baked into the image — see §9, do **not** hand-edit a running container.
- **RHEL Podman hosts** (Plan B infrastructure). Same algorithm intent applies, but the systemd unit is `sshd` (not `ssh`) and directive naming differs by version; handle under a separate CR.
- TLS/cert findings (e.g. the apt repository CA issue) — unrelated, tracked separately.

## 3. Risk Assessment & Impact

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **Applying Variant A (sntrup761) to an 8.2p1 production IPC** → `sshd -t` rejects the unknown KEX, sshd fails to come up cleanly → remote access lost to a deployed robot. | Medium if procedure skipped | High | Mandatory version detection (§6.2); use the auto-detecting deploy script (Appendix C). `sshd -t` gate before any reload. |
| R2 | Removing `ecdsa-sha2-nistp256` from accepted **user** key types locks out an account/automation that authenticates with an ECDSA key. | Low | High | Mandatory pre-check grep of `authorized_keys` (§6.3). Re-add to `PubkeyAcceptedKeyTypes` only if a key is found. |
| R3 | `restart` (vs `reload`) drops the operator's own live session mid-change. | Low | Medium | Procedure mandates `systemctl reload ssh`, never `restart`. |
| R4 | Operator's editing session is the only access path; a bad config closes it with no fallback. | Low | High | Keep current session open; open a **second** session to confirm before closing the first (§6.6). On-site team (plant) retains physical/VNC console fallback. |
| R5 | Change applied during an active production run disrupts the robot. | Low | Medium | Apply only within an agreed maintenance/commissioning window per the franchise model (CoE issues standard; plant schedules and executes). |

Reversibility: the entire change is one drop-in file. Backout = restore backup (or delete the file) + `reload`. No host-key regeneration, no package change, no reboot.

## 4. Configuration Standard

The hardening is delivered as a single file: `/etc/ssh/sshd_config.d/90-vce-hardening.conf`. The base `sshd_config` already contains `Include /etc/ssh/sshd_config.d/*.conf` and sets no algorithm directives, so the drop-in is authoritative (first-match wins).

Shared across both variants:

```
MACs            hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms       rsa-sha2-512,rsa-sha2-256,ssh-ed25519
PubkeyAcceptedKeyTypes  rsa-sha2-512,rsa-sha2-256,ssh-ed25519
```

`PubkeyAcceptedKeyTypes` is used (not `PubkeyAcceptedAlgorithms`) because the latter does not exist on 8.2p1; the `KeyTypes` spelling is valid on both 8.2 and 8.9.

KEX line differs by version — full files in **Appendix A (≥ 8.5)** and **Appendix B (8.2.x)**.

## 5. Pre-Implementation Checklist

- [ ] Change window agreed with plant owner; robot idle / not mid-task.
- [ ] Core Team approval recorded (Approver sign-off, §10).
- [ ] Out-of-band / console fallback confirmed available with on-site team.
- [ ] Target OpenSSH version recorded (§6.2).
- [ ] `authorized_keys` ECDSA pre-check run and clear, or exception noted (§6.3).
- [ ] Current `ssh-audit` baseline captured for the host.

## 6. Implementation Procedure

> Execute per host, inside the maintenance window. The auto-detecting script in **Appendix C** performs steps 6.2–6.7 with built-in rollback and is the recommended method for fleet rollout. The manual steps below are the equivalent and the basis for review.

**6.1 — Open a working session and keep it open.** Do not close this session until verification (6.8) passes from a second session.

**6.2 — Detect OpenSSH version (selects the variant).**
```bash
ssh -V 2>&1
VER=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+'); echo "OpenSSH ${VER}"
```
`8.5` or higher → Variant A. `8.2`/`8.4` → Variant B.

**6.3 — ECDSA user-key pre-check (R2 gate).**
```bash
grep -rIl ecdsa /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```
No output → proceed. If a file is listed, append `,ecdsa-sha2-nistp256` to the `PubkeyAcceptedKeyTypes` line of the drop-in (and only that line) before applying.

**6.4 — Back up any existing drop-in.**
```bash
F=/etc/ssh/sshd_config.d/90-vce-hardening.conf
[ -f "$F" ] && sudo cp -a "$F" "${F}.bak-$(date +%Y%m%d-%H%M%S)"
```

**6.5 — Write the correct variant.** Copy Appendix A (≥ 8.5) or Appendix B (8.2.x) to `$F`.

**6.6 — Validate (mandatory gate — do not skip).**
```bash
sudo sshd -t
```
Must return clean (no output). **If it errors, stop, restore the backup (or delete the file), and do not reload.**

**6.7 — Reload (not restart).**
```bash
sudo systemctl reload ssh
```

**6.8 — Verify from a SECOND session before closing the first.**
```bash
ssh movai@<host>           # new terminal — confirm you can log in
ssh-audit 127.0.0.1        # on the host
```

## 7. Validation / Acceptance Criteria

- [ ] `sshd -t` clean.
- [ ] New SSH session establishes successfully (second-session test passed).
- [ ] `ssh-audit 127.0.0.1` shows **no `[fail]` and no `[warn]`** in KEX, host-key, cipher, MAC sections. (The `kex-strict-s-v00@openssh.com` line is expected and is the Terrapin/CVE-2023-48795 mitigation — informational, not a finding.)
- [ ] Corporate vulnerability rescan confirms **finding 38909 closed**. This rescan is the formal acceptance gate; `ssh-audit` is the local proxy check.

Residual informational items (not blockers, see §8):
- Terrapin note on `chacha20-poly1305@openssh.com` — mitigated by strict-kex; relevant only against an unpatched peer.
- DHEat (CVE-2002-20001) connection-throttling note — addressed by the optional firewall control in Appendix D.

## 8. Rollback / Backout

If verification fails or remote access degrades:

```bash
F=/etc/ssh/sshd_config.d/90-vce-hardening.conf
# Restore previous drop-in if one was backed up …
sudo mv "$(ls -1t ${F}.bak-* 2>/dev/null | head -1)" "$F" 2>/dev/null || sudo rm -f "$F"
sudo sshd -t && sudo systemctl reload ssh
```

Removing the drop-in returns sshd to its prior (default) behaviour. If the working session was lost before backout, the on-site team restores via local console / VNC. No reboot required.

## 9. Post-Implementation — Persistence & Image Bake-in

Applying the drop-in to a running host fixes that host **only until it is re-flashed**. Korea and Sweden robots are (re)imaged from the DUSH golden image; a hand-applied file is wiped on re-flash and finding 38909 reopens.

To make the standard durable (config-as-code, per CoE governance):

1. Add `90-vce-hardening.conf` (correct variant for the image's OpenSSH version) to the DUSH golden image build under `/etc/ssh/sshd_config.d/`.
2. Record the image revision that first includes it.
3. New robots then ship hardened with no per-host manual step; this CR's manual procedure becomes the remediation path for already-deployed units only.

## 10. Approvals

| Role | Name | Decision | Date | Signature |
|---|---|---|---|---|
| Author / Implementer | VCE AMR Core TEam | Raised | 2026-06-16 | |
| Approver | Atair Camargo | ☐ Approve ☐ Reject | | |
| Verifier | Bruno Oliveira | ☐ Verified | | |
| Plant change owner | _(per site)_ | ☐ Window agreed | | |

---

## Appendix A — Drop-in (OpenSSH ≥ 8.5; e.g. Jammy 8.9p1 dev/VM)

```
# /etc/ssh/sshd_config.d/90-vce-hardening.conf
# VCE AMR SSH hardening — vuln 38909 (SHA-1 removal) + ecdsa drop + post-quantum KEX
# Target: OpenSSH >= 8.5
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
PubkeyAcceptedKeyTypes rsa-sha2-512,rsa-sha2-256,ssh-ed25519
```

## Appendix B — Drop-in (OpenSSH 8.2.x; production IPC, Ubuntu 20.04)

```
# /etc/ssh/sshd_config.d/90-vce-hardening.conf
# VCE AMR SSH hardening — vuln 38909 (SHA-1 removal) + ecdsa drop
# Target: OpenSSH 8.2.x  (NO sntrup761 — unsupported before 8.5)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
PubkeyAcceptedKeyTypes rsa-sha2-512,rsa-sha2-256,ssh-ed25519
```

> Note: presence of the Terrapin strict-kex marker depends on the OpenSSH build/backport. Confirm per platform with `ssh-audit`; absence is a build limitation, not a config error, and does not affect closure of 38909.

## Appendix C — Auto-detecting deploy script

Selects the variant by detected version, validates before applying, and rolls back automatically on `sshd -t` failure.

```bash
#!/usr/bin/env bash
# deploy_ssh_hardening.sh — VCE AMR fleet. Run as root within a change window.
set -euo pipefail

DROPIN=/etc/ssh/sshd_config.d/90-vce-hardening.conf
TS=$(date +%Y%m%d-%H%M%S)

# R2 gate: warn if ECDSA user keys exist (this standard drops ecdsa acceptance).
if grep -rIlq ecdsa /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null; then
  echo "WARNING: ECDSA user key(s) found. This standard removes ecdsa acceptance." >&2
  echo "         Review §6.3 before continuing. Aborting for safety." >&2
  exit 2
fi

# Backup existing drop-in.
[ -f "$DROPIN" ] && cp -a "$DROPIN" "${DROPIN}.bak-${TS}"

# Detect OpenSSH major.minor.
VER=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
MAJ=${VER%.*}; MIN=${VER#*.}

BASE_KEX="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
if [ "$MAJ" -gt 8 ] || { [ "$MAJ" -eq 8 ] && [ "$MIN" -ge 5 ]; }; then
  KEX="sntrup761x25519-sha512@openssh.com,${BASE_KEX}"   # Variant A
else
  KEX="${BASE_KEX}"                                       # Variant B
fi

cat > "$DROPIN" <<EOF
# VCE AMR SSH hardening — vuln 38909 (SHA-1 removal) + ecdsa drop + PQ KEX where supported
# Auto-generated for OpenSSH ${VER} on $(hostname) at ${TS}
KexAlgorithms ${KEX}
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
PubkeyAcceptedKeyTypes rsa-sha2-512,rsa-sha2-256,ssh-ed25519
EOF

# Validate; roll back on failure.
if ! sshd -t; then
  echo "ERROR: sshd -t failed — rolling back." >&2
  if [ -f "${DROPIN}.bak-${TS}" ]; then mv "${DROPIN}.bak-${TS}" "$DROPIN"; else rm -f "$DROPIN"; fi
  exit 1
fi

systemctl reload ssh
echo "OK: hardening applied for OpenSSH ${VER}. Verify in a SECOND session, then: ssh-audit 127.0.0.1"
```

## Appendix D — Optional control: DHEat DoS (CVE-2002-20001)

`ssh-audit` flags possible exposure to the DHEat key-exchange DoS via insufficient connection throttling. On a segmented robot network this exposure is low, but corporate scans may still raise it. Mitigate at the firewall (version-independent — the sshd `PerSourceMaxStartups` option only exists in OpenSSH ≥ 9.5 and will not parse on 8.2/8.9):

```bash
sudo ufw limit 22/tcp        # rate-limits repeated connections per source
```

Alternatively suppress the local test once judged out of scope: `ssh-audit --skip-rate-test 127.0.0.1`.

## Appendix E — References

- Finding 38909 — SHA1 deprecated setting for SSH (corporate scan).
- CVE-2023-48795 — Terrapin prefix-truncation (mitigated by strict-kex).
- CVE-2002-20001 — DHEat DoS (Appendix D).
- ssh-audit hardening guides: https://www.ssh-audit.com/hardening_guides.html
- Validation baseline: MovAI dev VM, OpenSSH 8.9p1, `ssh-audit` clean post-change.

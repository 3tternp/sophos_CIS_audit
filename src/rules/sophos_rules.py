from __future__ import annotations

import re
from typing import Callable, List

from ..core.corpus import ConfigCorpus
from ..core.engine import Finding, STATUS_PASS, STATUS_FAIL, STATUS_MANUAL, _mk
from ..core.corpus import Evidence

RuleFn = Callable[[ConfigCorpus], Finding]



def _manual(issue_id: str, name: str, fix_type: str, remediation: str, hint: str) -> Finding:
    return _mk(issue_id, name, STATUS_MANUAL, fix_type, remediation, [Evidence(file="(manual)", snippet=hint)])


def _enabled(c: ConfigCorpus, pattern: str) -> bool:
    return c.has(pattern + r".*(enable|enabled|on|true|1)")

def _disabled(c: ConfigCorpus, pattern: str) -> bool:
    return c.has(pattern + r".*(disable|disabled|off|false|0)")


# -------------------------
# Logging / Monitoring
# -------------------------

def rule_ntp_configured(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"\bntp\b.*(server|pool|host)", max_matches=3)
    if ev:
        return _mk("FW-LOG-003", "NTP is configured for time synchronization", STATUS_PASS, "Quick",
                   "Ensure NTP is configured with at least two reliable servers and is enforced on the firewall.", ev)
    ev2 = c.grep(r"<ntp[^>]*>|ntpserver|time\s*sync", max_matches=3)
    if ev2:
        return _mk("FW-LOG-003", "NTP is configured for time synchronization", STATUS_PASS, "Quick",
                   "Ensure NTP is configured with at least two reliable servers and is enforced on the firewall.", ev2)
    return _mk("FW-LOG-003", "NTP is configured for time synchronization", STATUS_MANUAL, "Quick",
               "Configure NTP on Sophos Firewall (System > Administration > Time).", None)


def rule_remote_syslog(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(remote\s+syslog|syslog\s+server|log\s+server|sysloghost)", max_matches=3)
    if ev:
        if c.has(r"(syslog|remote\s+syslog).*(enable|on|true|1)"):
            return _mk("FW-LOG-002", "Logs are forwarded to a remote syslog/SIEM", STATUS_PASS, "Quick",
                       "Forward logs to a centralized syslog/SIEM and monitor alerts.", ev)
        return _mk("FW-LOG-002", "Logs are forwarded to a remote syslog/SIEM", STATUS_MANUAL, "Quick",
                   "Enable remote syslog forwarding to SIEM and validate connectivity.", ev)
    return _mk("FW-LOG-002", "Logs are forwarded to a remote syslog/SIEM", STATUS_MANUAL, "Quick",
               "Enable remote syslog forwarding to SIEM and validate connectivity.", None)


def rule_log_dropped_traffic(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(log\s*(dropped|denied)|logdrop|logdeny|log\s+deny|log\s+drop)", max_matches=3)
    if ev and c.has(r"(log\s*(dropped|denied)|logdrop|logdeny).*(enable|on|true|1)"):
        return _mk("FW-LOG-001", "Denied/Dropped traffic logging is enabled", STATUS_PASS, "Quick",
                   "Enable logging for denied/dropped traffic (at minimum inbound) to support incident response.", ev)
    if ev and c.has(r"(log\s*(dropped|denied)|logdrop|logdeny).*(disable|off|false|0)"):
        return _mk("FW-LOG-001", "Denied/Dropped traffic logging is enabled", STATUS_FAIL, "Quick",
                   "Enable logging for denied/dropped traffic (at minimum inbound) to support incident response.", ev)
    return _mk("FW-LOG-001", "Denied/Dropped traffic logging is enabled", STATUS_MANUAL, "Quick",
               "Enable logging for denied/dropped traffic (at minimum inbound) to support incident response.", ev)


# -------------------------
# Administration / Management
# -------------------------

def rule_admin_on_wan_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(admin|management).*(wan|internet).*(enable|true|1)|wan\s*admin", max_matches=3)
    if ev and c.has(r"(disable\s*wan\s*admin|wan\s*admin\s*disable|no\s*wan\s*admin)"):
        return _mk("FW-ADM-002", "Administrative access is restricted (no management from WAN)", STATUS_PASS, "Quick",
                   "Ensure admin UI/SSH are not exposed on WAN; allow only from dedicated management networks.", ev)
    if ev:
        return _mk("FW-ADM-002", "Administrative access is restricted (no management from WAN)", STATUS_MANUAL, "Quick",
                   "Ensure admin UI/SSH are not exposed on WAN; allow only from dedicated management networks.", ev)
    # If we find clear indicators it's enabled, mark FAIL
    if c.has(r"(wan\s*?\-?\>?\s*admin|admin\s+on\s+wan|management\s+on\s+wan).*(enable|true|1)"):
        ev2 = c.grep(r"(wan\s*admin|admin\s+on\s+wan|management\s+on\s+wan).{0,80}", max_matches=3)
        return _mk("FW-ADM-002", "Administrative access is restricted (no management from WAN)", STATUS_FAIL, "Quick",
                   "Disable management access from WAN and restrict to management subnets/VPN.", ev2)
    return _mk("FW-ADM-002", "Administrative access is restricted (no management from WAN)", STATUS_MANUAL, "Quick",
               "Ensure admin UI/SSH are not exposed on WAN; allow only from dedicated management networks.", None)


def rule_admin_http_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(http\s*admin|admin\s*http|webadmin\s*http|management\s*http)", max_matches=3)
    if c.has(r"(http\s*admin|admin\s*http|webadmin\s*http).*(disable|off|false|0)"):
        return _mk("FW-ADM-001", "Administrative UI uses HTTPS only (HTTP disabled)", STATUS_PASS, "Quick",
                   "Disable HTTP management and enforce HTTPS for the administrative portal.", ev)
    if c.has(r"(http\s*admin|admin\s*http|webadmin\s*http).*(enable|on|true|1)"):
        return _mk("FW-ADM-001", "Administrative UI uses HTTPS only (HTTP disabled)", STATUS_FAIL, "Quick",
                   "Disable HTTP management and enforce HTTPS for the administrative portal.", ev)
    return _mk("FW-ADM-001", "Administrative UI uses HTTPS only (HTTP disabled)", STATUS_MANUAL, "Quick",
               "Disable HTTP management and enforce HTTPS for the administrative portal.", ev)


def rule_mfa_for_admins(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(mfa|two\s*factor|2fa|totp|otp).*(admin|user|login)", max_matches=3)
    if ev and c.has(r"(mfa|two\s*factor|2fa|totp|otp).*(enable|on|true|1)"):
        return _mk("FW-ADM-003", "Multi-factor authentication (MFA) is enabled for administrative access", STATUS_PASS, "Involved",
                   "Enable MFA for all administrator accounts and enforce it for all management access.", ev)
    if ev and c.has(r"(mfa|two\s*factor|2fa|totp|otp).*(disable|off|false|0)"):
        return _mk("FW-ADM-003", "Multi-factor authentication (MFA) is enabled for administrative access", STATUS_FAIL, "Involved",
                   "Enable MFA for all administrator accounts and enforce it for all management access.", ev)
    return _mk("FW-ADM-003", "Multi-factor authentication (MFA) is enabled for administrative access", STATUS_MANUAL, "Involved",
               "Enable MFA for all administrator accounts and enforce it for all management access.", ev)


def rule_password_policy(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(password\s*policy|min\s*password|complexity|lockout|failed\s*login)", max_matches=3)
    if ev and c.has(r"(min\s*password|minpass|minimum\s*password).*([1-9][0-9])"):
        return _mk("FW-ADM-005", "Password policy is configured (complexity/length/lockout)", STATUS_PASS, "Quick",
                   "Enforce strong password policy (length, complexity, lockout) for admins and local users.", ev)
    return _mk("FW-ADM-005", "Password policy is configured (complexity/length/lockout)", STATUS_MANUAL, "Quick",
               "Enforce strong password policy (length, complexity, lockout) for admins and local users.", ev)


def rule_ssh_disabled_or_restricted(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"\bssh\b.*(enable|disable|true|false|listen|port)", max_matches=3)
    if ev:
        if c.has(r"ssh.*(disable|off|false|0)"):
            return _mk("FW-ADM-006", "SSH management is disabled or strictly restricted", STATUS_PASS, "Quick",
                       "Disable SSH, or restrict it to a dedicated management interface and IP allowlist.", ev)
        if c.has(r"ssh.*(enable|on|true|1)"):
            return _mk("FW-ADM-006", "SSH management is disabled or strictly restricted", STATUS_FAIL, "Quick",
                       "Disable SSH, or restrict it to a dedicated management interface and IP allowlist.", ev)
        return _mk("FW-ADM-006", "SSH management is disabled or strictly restricted", STATUS_MANUAL, "Quick",
                   "Disable SSH, or restrict it to a dedicated management interface and IP allowlist.", ev)
    return _mk("FW-ADM-006", "SSH management is disabled or strictly restricted", STATUS_MANUAL, "Quick",
               "Disable SSH, or restrict it to a dedicated management interface and IP allowlist.", None)


def rule_snmp_disabled_or_restricted(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"\bsnmp\b.*(enable|disable|community|v3|user)", max_matches=3)
    if ev and c.has(r"snmp.*(disable|off|false|0)"):
        return _mk("FW-SVC-001", "SNMP is disabled or restricted to approved managers", STATUS_PASS, "Quick",
                   "Disable SNMP if not required, or restrict to SNMPv3 and approved manager IPs.", ev)
    if ev and c.has(r"snmp.*(enable|on|true|1)"):
        return _mk("FW-SVC-001", "SNMP is disabled or restricted to approved managers", STATUS_MANUAL, "Quick",
                   "If SNMP is enabled, use SNMPv3 and restrict to approved manager IPs.", ev)
    return _mk("FW-SVC-001", "SNMP is disabled or restricted to approved managers", STATUS_MANUAL, "Quick",
               "Disable SNMP if not required, or restrict to SNMPv3 and approved manager IPs.", ev)


def rule_upnp_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"\bupnp\b.*(enable|disable|true|false|1|0)", max_matches=3)
    if ev and c.has(r"upnp.*(disable|off|false|0)"):
        return _mk("FW-SVC-002", "UPnP is disabled", STATUS_PASS, "Quick",
                   "Disable UPnP to prevent unmanaged port mappings.", ev)
    if ev and c.has(r"upnp.*(enable|on|true|1)"):
        return _mk("FW-SVC-002", "UPnP is disabled", STATUS_FAIL, "Quick",
                   "Disable UPnP to prevent unmanaged port mappings.", ev)
    return _mk("FW-SVC-002", "UPnP is disabled", STATUS_MANUAL, "Quick",
               "Disable UPnP to prevent unmanaged port mappings.", ev)


# -------------------------
# Cryptography
# -------------------------

def rule_tls_legacy_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(tls\s*1\.0|tls\s*1\.1|ssl\s*v3|sslv3)", max_matches=3)
    if ev:
        if c.has(r"(disable|off|false|0).*(tls\s*1\.0|tls\s*1\.1|sslv3)") or c.has(r"(min\s*tls|min_tls).*(1\.2|tls1\.2)"):
            return _mk("FW-CRY-002", "Legacy TLS versions (1.0/1.1) are disabled", STATUS_PASS, "Involved",
                       "Confirm TLS 1.0/1.1 are disabled; enforce TLS 1.2+ on all management and user portals.", ev)
        return _mk("FW-CRY-002", "Legacy TLS versions (1.0/1.1) are disabled", STATUS_MANUAL, "Involved",
                   "Confirm TLS 1.0/1.1 are disabled; enforce TLS 1.2+ on all management and user portals.", ev)
    # No mention -> unknown
    return _mk("FW-CRY-002", "Legacy TLS versions (1.0/1.1) are disabled", STATUS_MANUAL, "Involved",
               "Confirm TLS 1.0/1.1 are disabled; enforce TLS 1.2+ on all management and user portals.", None)


def rule_ipsec_strong_crypto(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(ipsec|ike|phase\s*1|phase\s*2).*(aes|sha|dh|group|modp|gcm|3des|md5)", max_matches=3)
    if not ev:
        return _mk("FW-CRY-001", "IPsec VPN uses strong cryptography (AES/SHA-2, DH>=14)", STATUS_MANUAL, "Involved",
                   "Ensure IPsec uses AES (preferably AES-GCM), SHA-2, and DH group 14+; disable 3DES/MD5/SHA1.", None)

    weak = c.has(r"(3des|des\b|md5|sha1|group\s*2|modp1024)")
    strong = c.has(r"(aes\b|aes-?256|gcm|sha256|sha384|sha512|group\s*1[4-9]|group\s*2[0-9]|modp2048|modp3072)")
    if strong and not weak:
        return _mk("FW-CRY-001", "IPsec VPN uses strong cryptography (AES/SHA-2, DH>=14)", STATUS_PASS, "Involved",
                   "Ensure IPsec uses AES (preferably AES-GCM), SHA-2, and DH group 14+; disable 3DES/MD5/SHA1.", ev)
    if weak:
        return _mk("FW-CRY-001", "IPsec VPN uses strong cryptography (AES/SHA-2, DH>=14)", STATUS_FAIL, "Involved",
                   "Replace weak VPN algorithms (3DES/MD5/SHA1/DH group2) with AES/SHA-2 and DH group 14+.", ev)
    return _mk("FW-CRY-001", "IPsec VPN uses strong cryptography (AES/SHA-2, DH>=14)", STATUS_MANUAL, "Involved",
               "Ensure IPsec uses AES (preferably AES-GCM), SHA-2, and DH group 14+; disable 3DES/MD5/SHA1.", ev)


# -------------------------
# Network / Policy controls
# -------------------------

def rule_any_any_inbound(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(wan\s*->\s*lan|wan\s*to\s*lan|incoming).*(any|all).*(any|all).*(allow|accept|permit)", max_matches=3)
    if ev:
        return _mk("FW-NET-001", "No overly-permissive inbound rules (WAN -> LAN any/any allow)", STATUS_FAIL, "Involved",
                   "Review WAN->LAN rules to ensure least privilege; block any/any allows and restrict by source, service and destination.", ev)

    # also catch generic any/any allows that mention WAN/internet
    ev2 = c.grep(r"(rule|firewall|policy).*(any|all).*(any|all).*(allow|accept|permit).*(wan|internet)", max_matches=3)
    if ev2:
        return _mk("FW-NET-001", "No overly-permissive inbound rules (WAN -> LAN any/any allow)", STATUS_FAIL, "Involved",
                   "Review WAN->LAN rules to ensure least privilege; block any/any allows and restrict by source, service and destination.", ev2)

    return _mk("FW-NET-001", "No overly-permissive inbound rules (WAN -> LAN any/any allow)", STATUS_MANUAL, "Involved",
               "Review WAN->LAN rules to ensure least privilege; block any/any allows and restrict by source, service and destination.", None)


def rule_default_deny_inbound(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(default\s*deny|default\s*drop|implicit\s*deny)", max_matches=3)
    if ev:
        return _mk("FW-NET-002", "Inbound traffic has a default deny posture", STATUS_PASS, "Quick",
                   "Ensure inbound policies follow a default deny posture; allow only explicit required services.", ev)
    return _mk("FW-NET-002", "Inbound traffic has a default deny posture", STATUS_MANUAL, "Quick",
               "Ensure inbound policies follow a default deny posture; allow only explicit required services.", ev)


def rule_antispoof_bogon_enabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(bogon|antispoof|anti-spoof|spoof\s*protection|martian|rfc1918)", max_matches=3)
    if ev and c.has(r"(bogon|antispoof|anti-spoof|spoof\s*protection).*(enable|on|true|1)"):
        return _mk("FW-NET-003", "Anti-spoofing/bogon filtering is enabled on WAN", STATUS_PASS, "Quick",
                   "Enable anti-spoofing/bogon filtering on WAN interfaces to block invalid source IP space.", ev)
    if ev and c.has(r"(bogon|antispoof|anti-spoof|spoof\s*protection).*(disable|off|false|0)"):
        return _mk("FW-NET-003", "Anti-spoofing/bogon filtering is enabled on WAN", STATUS_FAIL, "Quick",
                   "Enable anti-spoofing/bogon filtering on WAN interfaces to block invalid source IP space.", ev)
    return _mk("FW-NET-003", "Anti-spoofing/bogon filtering is enabled on WAN", STATUS_MANUAL, "Quick",
               "Enable anti-spoofing/bogon filtering on WAN interfaces to block invalid source IP space.", ev)


# -------------------------
# Threat Prevention
# -------------------------

def rule_ips_enabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(ips|intrusion\s*prevention).*(enable|true|1|profile|policy)", max_matches=3)
    if ev:
        if c.has(r"(ips|intrusion\s*prevention).*(disable|off|false|0)"):
            return _mk("FW-TP-001", "IPS/Intrusion Prevention is enabled on relevant policies", STATUS_MANUAL, "Involved",
                       "Confirm IPS is enabled and applied to relevant firewall rules.", ev)
        return _mk("FW-TP-001", "IPS/Intrusion Prevention is enabled on relevant policies", STATUS_PASS, "Involved",
                   "Enable IPS for internet-facing and high-risk policies; ensure updates are current.", ev)
    ev2 = c.grep(r"\bintrusion\b|\bips\b", max_matches=3)
    if ev2:
        return _mk("FW-TP-001", "IPS/Intrusion Prevention is enabled on relevant policies", STATUS_MANUAL, "Involved",
                   "Confirm IPS is enabled and applied to relevant firewall rules.", ev2)
    return _mk("FW-TP-001", "IPS/Intrusion Prevention is enabled on relevant policies", STATUS_MANUAL, "Involved",
               "Enable IPS and ensure it is applied to relevant firewall rules.", None)


def rule_auto_updates_enabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(auto\s*update|automatic\s*update|signature\s*update|pattern\s*update|firmware\s*update)", max_matches=3)
    if ev and c.has(r"(auto\s*update|automatic\s*update|signature\s*update|pattern\s*update).*(enable|on|true|1)"):
        return _mk("FW-TP-002", "Automatic security/signature updates are enabled", STATUS_PASS, "Quick",
                   "Enable automatic updates for IPS/AV/web signatures and ensure update schedules are active.", ev)
    if ev and c.has(r"(auto\s*update|automatic\s*update|signature\s*update|pattern\s*update).*(disable|off|false|0)"):
        return _mk("FW-TP-002", "Automatic security/signature updates are enabled", STATUS_FAIL, "Quick",
                   "Enable automatic updates for IPS/AV/web signatures and ensure update schedules are active.", ev)
    return _mk("FW-TP-002", "Automatic security/signature updates are enabled", STATUS_MANUAL, "Quick",
               "Enable automatic updates for IPS/AV/web signatures and ensure update schedules are active.", ev)


def rule_web_filtering_enabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(web\s*filter|url\s*filter|category\s*filter|web\s*protection)", max_matches=3)
    if ev and c.has(r"(web\s*filter|url\s*filter|web\s*protection).*(enable|on|true|1)"):
        return _mk("FW-TP-003", "Web/URL filtering is enabled for user egress where applicable", STATUS_PASS, "Planned",
                   "Enable web filtering for user egress according to policy; log and monitor blocks.", ev)
    return _mk("FW-TP-003", "Web/URL filtering is enabled for user egress where applicable", STATUS_MANUAL, "Planned",
               "Enable web filtering for user egress according to policy; log and monitor blocks.", ev)


def rule_antimalware_scanning_enabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(anti-?virus|av\b|malware|content\s*scanning|dpi\s*engine)", max_matches=3)
    if ev and c.has(r"(anti-?virus|malware|content\s*scanning).*(enable|on|true|1)"):
        return _mk("FW-TP-004", "Malware/AV scanning is enabled where applicable", STATUS_PASS, "Planned",
                   "Enable anti-malware scanning features for applicable traffic (web/proxy/email as licensed).", ev)
    return _mk("FW-TP-004", "Malware/AV scanning is enabled where applicable", STATUS_MANUAL, "Planned",
               "Enable anti-malware scanning features for applicable traffic (web/proxy/email as licensed).", ev)




# -------------------------
# Additional Best Practice / Insurance-oriented
# -------------------------

def rule_admin_session_timeout(c: ConfigCorpus) -> Finding:
    # Look for session timeout values (minutes/seconds)
    ev = c.grep(r"(session\s*timeout|idle\s*timeout|admin\s*timeout)\s*[=:]\s*(\d+)", max_matches=3)
    if ev:
        # Try to extract a number and flag if overly long (> 15 minutes)
        nums = []
        for e in ev:
            m = re.search(r"(\d+)", e.snippet)
            if m:
                nums.append(int(m.group(1)))
        if nums and max(nums) <= 15:
            return _mk("FW-ADM-007", "Administrative session timeout is configured (<=15 minutes)", STATUS_PASS, "Quick",
                       "Set administrative session/idle timeout to 10–15 minutes to reduce risk of unattended sessions.", ev)
        return _mk("FW-ADM-007", "Administrative session timeout is configured (<=15 minutes)", STATUS_FAIL, "Quick",
                   "Set administrative session/idle timeout to 10–15 minutes to reduce risk of unattended sessions.", ev)
    return _manual("FW-ADM-007", "Administrative session timeout is configured (<=15 minutes)", "Quick",
                   "Set administrative session/idle timeout to 10–15 minutes to reduce risk of unattended sessions.",
                   "SFOS: Administration > Admin settings (or System > Administration) — verify idle/session timeout value.")


def rule_admin_lockout_bruteforce(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(login\s*attempt|failed\s*login|lockout|brute\s*force).*?(enable|enabled|on|true|1)|account\s*lockout", max_matches=3)
    if ev:
        return _mk("FW-ADM-008", "Account lockout / brute-force protection is enabled for admin logins", STATUS_PASS, "Quick",
                   "Enable account lockout / brute-force protections for administrative logins and tune thresholds appropriately.", ev)
    return _manual("FW-ADM-008", "Account lockout / brute-force protection is enabled for admin logins", "Quick",
                   "Enable account lockout / brute-force protections for administrative logins and tune thresholds appropriately.",
                   "SFOS: Administration > Admin settings — verify failed-login lockout / protection options.")


def rule_telnet_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"telnet.*(enable|enabled|on|true|1)", max_matches=3)
    if ev:
        return _mk("FW-SVC-003", "Telnet management is disabled", STATUS_FAIL, "Quick",
                   "Disable Telnet management access; use SSH with restricted management IPs and strong ciphers if remote CLI is required.", ev)
    if c.has(r"telnet.*(disable|disabled|off|false|0)"):
        ev2 = c.grep(r"telnet.*(disable|disabled|off|false|0)", max_matches=3)
        return _mk("FW-SVC-003", "Telnet management is disabled", STATUS_PASS, "Quick",
                   "Disable Telnet management access; use SSH with restricted management IPs and strong ciphers if remote CLI is required.", ev2)
    return _manual("FW-SVC-003", "Telnet management is disabled", "Quick",
                   "Disable Telnet management access; use SSH with restricted management IPs and strong ciphers if remote CLI is required.",
                   "SFOS: Administration > Device access — confirm Telnet is disabled on all zones.")


def rule_wan_ping_disabled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(respond\s*to\s*ping|icmp\s*respond|wan\s*ping).*?(enable|enabled|on|true|1)", max_matches=3)
    if ev:
        return _mk("FW-NET-004", "WAN ping/ICMP response is disabled (unless required)", STATUS_FAIL, "Quick",
                   "Disable responding to ping/ICMP on WAN to reduce reconnaissance surface, unless explicitly required.", ev)
    if c.has(r"(respond\s*to\s*ping|icmp\s*respond|wan\s*ping).*?(disable|disabled|off|false|0)"):
        ev2 = c.grep(r"(respond\s*to\s*ping|icmp\s*respond|wan\s*ping).*?(disable|disabled|off|false|0)", max_matches=3)
        return _mk("FW-NET-004", "WAN ping/ICMP response is disabled (unless required)", STATUS_PASS, "Quick",
                   "Disable responding to ping/ICMP on WAN to reduce reconnaissance surface, unless explicitly required.", ev2)
    return _manual("FW-NET-004", "WAN ping/ICMP response is disabled (unless required)", "Quick",
                   "Disable responding to ping/ICMP on WAN to reduce reconnaissance surface, unless explicitly required.",
                   "SFOS: Administration > Device access / WAN settings — confirm 'Respond to ping' is disabled on WAN.")


def rule_admin_audit_logging(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(admin|administrator).*?(audit|activity).*?(log|logging).*?(enable|enabled|on|true|1)", max_matches=3)
    if ev:
        return _mk("FW-LOG-004", "Administrative/audit logging is enabled", STATUS_PASS, "Quick",
                   "Enable administrative/audit logging and forward logs to SIEM for monitoring and investigation.", ev)
    return _manual("FW-LOG-004", "Administrative/audit logging is enabled", "Quick",
                   "Enable administrative/audit logging and forward logs to SIEM for monitoring and investigation.",
                   "SFOS: Logs & Reports — verify admin events/audit logs are enabled and retained/forwarded.")


def rule_backup_scheduled(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(backup\s*schedule|scheduled\s*backup|auto\s*backup).*?(enable|enabled|on|true|1)|cron.*backup", max_matches=3)
    if ev:
        return _mk("FW-BKP-001", "Scheduled backups are enabled and stored securely", STATUS_PASS, "Planned",
                   "Enable scheduled backups, encrypt them, and store them in a restricted repository. Test restore periodically.", ev)
    return _manual("FW-BKP-001", "Scheduled backups are enabled and stored securely", "Planned",
                   "Enable scheduled backups, encrypt them, and store them in a restricted repository. Test restore periodically.",
                   "SFOS: Backup & Firmware — verify scheduled backups (frequency, encryption) and secure storage process.")


def rule_siem_forwarding_required_insurance(c: ConfigCorpus) -> Finding:
    # Insurance-sector best practice: SIEM forwarding should be in place.
    ev = c.grep(r"(syslog|siem|log\s*forward).*?(enable|enabled|on|true|1)|remote\s*syslog", max_matches=3)
    if ev:
        return _mk("INS-LOG-001", "Centralized log forwarding to SIEM is configured (insurance best practice)", STATUS_PASS, "Quick",
                   "Ensure firewall logs (traffic, security events, admin activity) are forwarded to SIEM with reliable connectivity and retention.", ev)
    # If we find explicit disabled indicator
    ev2 = c.grep(r"(syslog|remote\s*syslog|log\s*forward).*?(disable|disabled|off|false|0)", max_matches=3)
    if ev2:
        return _mk("INS-LOG-001", "Centralized log forwarding to SIEM is configured (insurance best practice)", STATUS_FAIL, "Quick",
                   "Enable log forwarding to SIEM and validate delivery. This is typically required for auditability and incident response in regulated sectors.", ev2)
    return _manual("INS-LOG-001", "Centralized log forwarding to SIEM is configured (insurance best practice)", "Quick",
                   "Enable log forwarding to SIEM and validate delivery. This is typically required for auditability and incident response in regulated sectors.",
                   "SFOS: System Services > Log settings / Syslog server — confirm at least one remote syslog/SIEM destination is enabled.")


def rule_mgmt_access_allowlist_insurance(c: ConfigCorpus) -> Finding:
    ev = c.grep(r"(admin|management).*(allowlist|whitelist|permitted\s*ip|permitted\s*network)", max_matches=3)
    if ev:
        return _mk("INS-ADM-001", "Management access is restricted to an allowlist (insurance best practice)", STATUS_PASS, "Quick",
                   "Restrict administrative access to explicit management networks (allowlist) and enforce MFA.", ev)
    return _manual("INS-ADM-001", "Management access is restricted to an allowlist (insurance best practice)", "Quick",
                   "Restrict administrative access to explicit management networks (allowlist) and enforce MFA.",
                   "SFOS: Administration > Device access / Admin settings — confirm management services are limited to management subnets only.")


def default_rules() -> List[RuleFn]:
    return [
        # Logging / Monitoring
        rule_ntp_configured,
        rule_remote_syslog,
        rule_log_dropped_traffic,

        # Admin / Mgmt
        rule_admin_http_disabled,
        rule_admin_on_wan_disabled,
        rule_mfa_for_admins,
        rule_password_policy,
        rule_ssh_disabled_or_restricted,
        rule_snmp_disabled_or_restricted,
        rule_upnp_disabled,

        # Crypto
        rule_tls_legacy_disabled,
        rule_ipsec_strong_crypto,

        # Network / Policy
        rule_default_deny_inbound,
        rule_any_any_inbound,
        rule_antispoof_bogon_enabled,

        # Threat prevention
        rule_ips_enabled,
        rule_auto_updates_enabled,
        rule_web_filtering_enabled,
        rule_antimalware_scanning_enabled,
        rule_admin_session_timeout,
        rule_admin_lockout_bruteforce,
        rule_telnet_disabled,
        rule_admin_audit_logging,
        rule_wan_ping_disabled,
        rule_backup_scheduled,
        rule_siem_forwarding_required_insurance,
        rule_mgmt_access_allowlist_insurance,
    ]

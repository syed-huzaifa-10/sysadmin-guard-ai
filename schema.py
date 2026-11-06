"""Input facts the user can set in the UI (the initial working memory)."""
B, I, F, S = "bool", "int", "float", "select"

# key, label, kind, default (= hardened value), range/options, group
FIELDS = [
    ("firewall_enabled", "Host firewall active", B, True, None, "Network"),
    ("open_ports_count", "Listening ports", I, 6, (0, 100), "Network"),
    ("telnet_enabled", "Telnet enabled", B, False, None, "Network"),
    ("ftp_enabled", "Plain FTP enabled", B, False, None, "Network"),
    ("ip_forwarding_enabled", "IP forwarding enabled", B, False, None, "Network"),
    ("icmp_redirects_accepted", "ICMP redirects accepted", B, False, None, "Network"),
    ("syn_cookies_enabled", "TCP SYN cookies enabled", B, True, None, "Network"),
    ("fail2ban_installed", "fail2ban / sshguard installed", B, True, None, "Network"),

    ("ssh_root_login", "SSH root login permitted", B, False, None, "Authentication"),
    ("ssh_password_auth", "SSH password auth enabled", B, False, None, "Authentication"),
    ("ssh_permit_empty", "SSH permits empty passwords", B, False, None, "Authentication"),
    ("ssh_max_auth_tries", "SSH MaxAuthTries", I, 3, (1, 10), "Authentication"),
    ("mfa_enabled", "MFA enforced", B, True, None, "Authentication"),
    ("password_min_length", "Min password length", I, 14, (4, 32), "Authentication"),
    ("password_max_age_days", "Password max age (days)", I, 90, (0, 730), "Authentication"),
    ("account_lockout", "Account lockout policy", B, True, None, "Authentication"),
    ("empty_password_accounts", "Accounts with empty password", I, 0, (0, 20), "Authentication"),
    ("sudo_nopasswd", "Passwordless sudo configured", B, False, None, "Authentication"),
    ("uid0_accounts", "Accounts with UID 0 (incl. root)", I, 1, (1, 10), "Authentication"),
    ("failed_logins_24h", "Failed logins (24h)", I, 5, (0, 2000), "Authentication"),

    ("world_writable_files", "World-writable files", I, 0, (0, 500), "Filesystem"),
    ("tmp_noexec", "/tmp mounted noexec", B, True, None, "Filesystem"),
    ("shadow_perms_ok", "/etc/shadow perms correct (0640 or stricter)", B, True, None, "Filesystem"),
    ("suid_unknown_binaries", "Unknown SUID binaries", I, 0, (0, 50), "Filesystem"),
    ("disk_encryption", "Disk encryption (LUKS)", B, True, None, "Filesystem"),
    ("umask_secure", "Secure default umask (027+)", B, True, None, "Filesystem"),

    ("cpu_usage", "CPU usage %", I, 35, (0, 100), "Resources"),
    ("ram_usage", "RAM usage %", I, 55, (0, 100), "Resources"),
    ("swap_usage", "Swap usage %", I, 5, (0, 100), "Resources"),
    ("disk_usage", "Disk usage %", I, 50, (0, 100), "Resources"),
    ("inode_usage", "Inode usage %", I, 20, (0, 100), "Resources"),
    ("load_avg_per_core", "Load average per core", F, 0.5, (0.0, 8.0), "Resources"),
    ("zombie_processes", "Zombie processes", I, 0, (0, 100), "Resources"),
    ("uptime_days", "Uptime (days)", I, 40, (0, 1500), "Resources"),

    ("days_since_update", "Days since last patch run", I, 7, (0, 1000), "Patching"),
    ("pending_security_updates", "Pending security updates", I, 0, (0, 200), "Patching"),
    ("os_eol", "OS is end-of-life", B, False, None, "Patching"),
    ("auto_updates", "Automatic security updates", B, True, None, "Patching"),
    ("unneeded_services", "Unneeded services running", I, 1, (0, 30), "Patching"),
    ("kernel_outdated", "Running kernel outdated", B, False, None, "Patching"),

    ("auditd_enabled", "auditd enabled", B, True, None, "Logging & Audit"),
    ("remote_logging", "Logs shipped to remote server", B, True, None, "Logging & Audit"),
    ("log_retention_days", "Log retention (days)", I, 365, (0, 1000), "Logging & Audit"),
    ("ntp_sync", "Time sync (NTP/chrony)", B, True, None, "Logging & Audit"),
    ("logrotate_enabled", "logrotate configured", B, True, None, "Logging & Audit"),
    ("fim_enabled", "File integrity monitoring", B, True, None, "Logging & Audit"),

    ("backup_enabled", "Backups enabled", B, True, None, "Backup & Monitoring"),
    ("backup_age_days", "Age of latest backup (days)", I, 1, (0, 365), "Backup & Monitoring"),
    ("backup_tested", "Restore tested", B, True, None, "Backup & Monitoring"),
    ("backup_encrypted", "Backups encrypted", B, True, None, "Backup & Monitoring"),
    ("monitoring_agent", "Monitoring agent installed", B, True, None, "Backup & Monitoring"),

    ("mac_mode", "SELinux / AppArmor mode", S, "enforcing",
     ["enforcing", "permissive", "disabled"], "Security Controls"),
    ("edr_installed", "EDR / antimalware installed", B, True, None, "Security Controls"),
]

DEFAULTS = {f[0]: f[3] for f in FIELDS}
GROUPS = list(dict.fromkeys(f[5] for f in FIELDS))

PRESETS = {
    "Fresh Ubuntu install": dict(
        firewall_enabled=False, open_ports_count=8, ssh_password_auth=True, mfa_enabled=False,
        password_min_length=8, password_max_age_days=730, account_lockout=False,
        sudo_nopasswd=True, fail2ban_installed=False, auditd_enabled=False,
        remote_logging=False, log_retention_days=28, disk_encryption=False, fim_enabled=False,
        backup_enabled=False, monitoring_agent=False, edr_installed=False, unneeded_services=6),
    "Hardened production server": {},
    "Neglected legacy server": dict(
        firewall_enabled=False, open_ports_count=45, telnet_enabled=True, ftp_enabled=True,
        ip_forwarding_enabled=True, icmp_redirects_accepted=True, syn_cookies_enabled=False,
        fail2ban_installed=False, ssh_root_login=True, ssh_password_auth=True,
        ssh_permit_empty=True, ssh_max_auth_tries=10, mfa_enabled=False, password_min_length=6,
        password_max_age_days=730, account_lockout=False, empty_password_accounts=2,
        sudo_nopasswd=True, uid0_accounts=2, failed_logins_24h=850, world_writable_files=40,
        tmp_noexec=False, shadow_perms_ok=False, suid_unknown_binaries=3, disk_encryption=False,
        umask_secure=False, cpu_usage=96, ram_usage=93, swap_usage=70, disk_usage=94,
        inode_usage=90, load_avg_per_core=3.2, zombie_processes=25, uptime_days=700,
        days_since_update=400, pending_security_updates=85, os_eol=True, auto_updates=False,
        unneeded_services=12, kernel_outdated=True, auditd_enabled=False, remote_logging=False,
        log_retention_days=14, ntp_sync=False, logrotate_enabled=False, fim_enabled=False,
        backup_enabled=False, backup_age_days=120, backup_tested=False, backup_encrypted=False,
        monitoring_agent=False, mac_mode="disabled", edr_installed=False),
}

#!/usr/bin/env bats

load test_helper

@test "Verify that we're using Ubuntu" {
  run bash -c "lsb_release -i | grep 'Ubuntu'"
  [ "$status" -eq 0 ]
}

#Disablenets

@test "Verify that kernel module dccp is disabled" {
  run bash -c "grep 'install dccp /bin/true' $DISABLENET"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module sctp is disabled" {
  run bash -c "grep 'install sctp /bin/true' $DISABLENET"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module rds is disabled" {
  run bash -c "grep 'install rds /bin/true' $DISABLENET"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module tipc is disabled" {
  run bash -c "grep 'install tipc /bin/true' $DISABLENET"
  [ "$status" -eq 0 ]
}

#Disablemnts
@test "Verify that kernel module cramfs is disabled" {
  run bash -c "grep 'install cramfs /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module freevxfs is disabled" {
  run bash -c "grep 'install freevxfs /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module jffs2 is disabled" {
  run bash -c "grep 'install jffs2 /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module hfs is disabled" {
  run bash -c "grep 'install hfs /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module hfsplus is disabled" {
  run bash -c "grep 'install hfsplus /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module squashfs is disabled" {
  run bash -c "grep 'install squashfs /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module udf is disabled" {
  run bash -c "grep 'install udf /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module vfat is disabled" {
  run bash -c "grep 'install udf /bin/true' $DISABLEMNT"
  [ "$status" -eq 0 ]
}

#systemconf@test "Verify DumpCore in $SYSTEMCONF" {
  run bash -c "grep '^DumpCore=no$' $SYSTEMCONF"
  [ "$status" -eq 0 ]
}

@test "Verify CrashShell in $SYSTEMCONF" {
  run bash -c "grep '^CrashShell=no$' $SYSTEMCONF"
  [ "$status" -eq 0 ]
}

@test "Verify system DefaultLimitCORE in $SYSTEMCONF" {
  run bash -c "grep '^DefaultLimitCORE=0$' $SYSTEMCONF"
  [ "$status" -eq 0 ]
}

@test "Verify system DefaultLimitNOFILE in $SYSTEMCONF" {
  run bash -c "grep '^DefaultLimitNOFILE=100$' $SYSTEMCONF"
  [ "$status" -eq 0 ]
}

@test "Verify system DefaultLimitNPROC in $SYSTEMCONF" {
  run bash -c "grep '^DefaultLimitNPROC=100$' $SYSTEMCONF"
  [ "$status" -eq 0 ]
}

@test "Verify user DefaultLimitCORE in $USERCONF" {
  run bash -c "grep '^DefaultLimitCORE=0$' $USERCONF"
  [ "$status" -eq 0 ]
}

@test "Verify user DefaultLimitNOFILE in $USERCONF" {
  run bash -c "grep '^DefaultLimitNOFILE=100$' $USERCONF"
  [ "$status" -eq 0 ]
}

@test "Verify user DefaultLimitNPROC in $USERCONF" {
  run bash -c "grep '^DefaultLimitNPROC=100$' $USERCONF"
  [ "$status" -eq 0 ]
}

#Journalctl

@test "Verify that journald storage is persistent in $JOURNALDCONF" {
  run bash -c "grep '^Storage=persistent$' $JOURNALDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that journald forwards to syslog in $JOURNALDCONF" {
  run bash -c "grep '^ForwardToSyslog=yes$' $JOURNALDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that journald compresses logs in $JOURNALDCONF" {
  run bash -c "grep '^Compress=yes$' $JOURNALDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that logrotate compresses logs in $LOGROTATE" {
  run bash -c "grep '^compress$' $LOGROTATE"
  [ "$status" -eq 0 ]
}

#Timesyncd

@test "Verify that a NTP server is set in $TIMESYNCD" {
  run bash -c "grep '^NTP=...' $TIMESYNCD"
  [ "$status" -eq 0 ]
}

@test "Verify that a fallback NTP server is set in $TIMESYNCD" {
  run bash -c "grep '^FallbackNTP=...' $TIMESYNCD"
  [ "$status" -eq 0 ]
}

#fstabs
@test "Ensure a floppy isn't present in /etc/fstab" {
  run bash -c "grep floppy /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Ensure /tmp isn't present in /etc/fstab" {
  run bash -c "grep -e '[[:space:]]/tmp[[:space:]]' /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Ensure /var/tmp isn't present in /etc/fstab" {
  run bash -c "grep -e '[[:space:]]/var/tmp[[:space:]]' /etc/fstab"
  [ "$status" -eq 1 ]
}

@test "Verify that tmp.mount is enabled" {
  run bash -c "systemctl is-enabled tmp.mount"
  [ "$status" -eq 0 ]
}

@test "Verify that var-tmp.mount is enabled" {
  run bash -c "systemctl is-enabled var-tmp.mount"
  [ "$status" -eq 0 ]
}

@test "Verify that /tmp is mounted with nodev" {
  tmpMount=$(fragmentPath tmp.mount)
  run bash -c "grep '^Options=.*nodev.*' $tmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /tmp is mounted with nosuid" {
  tmpMount=$(fragmentPath tmp.mount)
  run bash -c "grep '^Options=.*nosuid.*' $tmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/tmp is mounted with nodev" {
  varTmpMount=$(fragmentPath var-tmp.mount)
  run bash -c "grep '^Options=.*nodev.*' $varTmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/tmp is mounted with nosuid" {
  varTmpMount=$(fragmentPath var-tmp.mount)
  run bash -c "grep '^Options=.*nosuid.*' $varTmpMount"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is a seperate partition" {
  run bash -c "grep '[[:space:]]/home[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is mounted with nodev" {
  run bash -c "grep '[[:space:]]/home[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /home is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/home[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log/audit is a seperate partition" {
  run bash -c "grep '[[:space:]]/var/log/audit[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log/audit is mounted with nodev" {
  run bash -c "grep '[[:space:]]/var/log/audit[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log/audit is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/var/log/audit[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log/audit is mounted with noexec" {
  run bash -c "grep '[[:space:]]/var/log/audit[[:space:]].*noexec.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log is a seperate partition" {
  run bash -c "grep '[[:space:]]/var/log[[:space:]]' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log is mounted with nodev" {
  run bash -c "grep '[[:space:]]/var/log[[:space:]].*nodev.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log is mounted with nosuid" {
  run bash -c "grep '[[:space:]]/var/log[[:space:]].*nosuid.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

@test "Verify that /var/log is mounted with noexec" {
  run bash -c "grep '[[:space:]]/var/log[[:space:]].*noexec.*' /proc/mounts"
  [ "$status" -eq 0 ]
}

#hosts

@test "Verify /etc/hosts.deny" {
  run bash -c "grep '^ALL: PARANOID$' /etc/hosts.deny"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/hosts.allow" {
  run bash -c "grep '^ALL: LOCAL, 127.0.0.1$' /etc/hosts.allow"
  [ "$status" -eq 0 ]
}

#logindefs
@test "Verify LOG_OK_LOGINS in $LOGINDEFS" {
  run bash -c "grep '^LOG_OK_LOGINS.*yes$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify UMASK in $LOGINDEFS" {
  run bash -c "grep '^UMASK.*077$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify PASS_MIN_DAYS in $LOGINDEFS" {
  run bash -c "grep '^PASS_MIN_DAYS.*7$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify PASS_MAX_DAYS in $LOGINDEFS" {
  run bash -c "grep '^PASS_MAX_DAYS.*30$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify DEFAULT_HOME in $LOGINDEFS" {
  run bash -c "grep '^DEFAULT_HOME no$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify USERGROUPS_ENAB in $LOGINDEFS" {
  run bash -c "grep '^USERGROUPS_ENAB no$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

@test "Verify SHA_CRYPT_MAX_ROUNDS in $LOGINDEFS" {
  run bash -c "grep '^SHA_CRYPT_MAX_ROUNDS.*10000$' $LOGINDEFS"
  [ "$status" -eq 0 ]
}

#systemctl
@test "Verify fs.protected_hardlinks in $SYSCTL" {
	run bash -c "grep '^fs.protected_hardlinks.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify fs.protected_symlinks in $SYSCTL" {
	run bash -c "grep '^fs.protected_symlinks.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify fs.suid_dumpable in $SYSCTL" {
	run bash -c "grep '^fs.suid_dumpable.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.core_uses_pid in $SYSCTL" {
	run bash -c "grep '^kernel.core_uses_pid.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.kptr_restrict in $SYSCTL" {
	run bash -c "grep '^kernel.kptr_restrict.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.panic in $SYSCTL" {
	run bash -c "grep '^kernel.panic.*60$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.panic_on_oops in $SYSCTL" {
	run bash -c "grep '^kernel.panic_on_oops.*60$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.perf_event_paranoid in $SYSCTL" {
	run bash -c "grep '^kernel.perf_event_paranoid.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.randomize_va_space in $SYSCTL" {
	run bash -c "grep '^kernel.randomize_va_space.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.sysrq in $SYSCTL" {
	run bash -c "grep '^kernel.sysrq.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify kernel.yama.ptrace_scope in $SYSCTL" {
	run bash -c "grep '^kernel.yama.ptrace_scope.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.accept_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.accept_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.accept_source_route in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.accept_source_route.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.log_martians in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.log_martians.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.rp_filter in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.rp_filter.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.secure_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.secure_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.all.send_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.all.send_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.accept_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.accept_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.accept_source_route in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.accept_source_route.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.log_martians in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.log_martians.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.rp_filter= in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.rp_filter=.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.secure_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.secure_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.conf.default.send_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv4.conf.default.send_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.icmp_echo_ignore_broadcasts in $SYSCTL" {
	run bash -c "grep '^net.ipv4.icmp_echo_ignore_broadcasts.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.icmp_ignore_bogus_error_responses in $SYSCTL" {
	run bash -c "grep '^net.ipv4.icmp_ignore_bogus_error_responses.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.ip_forward in $SYSCTL" {
	run bash -c "grep '^net.ipv4.ip_forward.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_challenge_ack_limit in $SYSCTL" {
  ack_limit_result=$(grep '^net.ipv4.tcp_challenge_ack_limit.*' $SYSCTL | awk '{print $NF >= 1000}')
  [ $ack_limit_result -eq 1 ]
}

@test "Verify net.ipv4.tcp_max_syn_backlog in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_max_syn_backlog.*2048$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_rfc1337 in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_rfc1337.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_synack_retries in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_synack_retries.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_syncookies in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_syncookies.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_syn_retries in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_syn_retries.*5$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv4.tcp_timestamps in $SYSCTL" {
	run bash -c "grep '^net.ipv4.tcp_timestamps.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.all.use_tempaddr in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.all.use_tempaddr.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.all.accept_ra in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.all.accept_ra.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.all.accept_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.all.accept_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.accept_ra in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.accept_ra.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.accept_ra_defrtr in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.accept_ra_defrtr.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.accept_ra_pinfo in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.accept_ra_pinfo.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.accept_redirects in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.accept_redirects.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.autoconf in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.autoconf.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.dad_transmits in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.dad_transmits.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.max_addresses in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.max_addresses.*1$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.router_solicitations in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.router_solicitations.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.default.use_tempaddr in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.default.use_tempaddr.*2$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.ipv6.conf.*.accept_ra_rtr_pref in $SYSCTL" {
	run bash -c "grep '^net.ipv6.conf.*.accept_ra_rtr_pref.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.netfilter.nf_conntrack_max in $SYSCTL" {
	run bash -c "grep '^net.netfilter.nf_conntrack_max.*2000000$' $SYSCTL"
	[ "$status" -eq 0 ]
}

@test "Verify net.netfilter.nf_conntrack_tcp_loose in $SYSCTL" {
	run bash -c "grep '^net.netfilter.nf_conntrack_tcp_loose.*0$' $SYSCTL"
	[ "$status" -eq 0 ]
}

#Limits

@test "Verify maxlogins in $LIMITSCONF" {
  run bash -c "grep '^* hard maxlogins 10$' $LIMITSCONF"
  [ "$status" -eq 0 ]
}

@test "Verify hard core in $LIMITSCONF" {
  run bash -c "grep '^* hard core 0$' $LIMITSCONF"
  [ "$status" -eq 0 ]
}

@test "Verify soft nproc in $LIMITSCONF" {
  run bash -c "grep '^* soft nproc 100$' $LIMITSCONF"
  [ "$status" -eq 0 ]
}

@test "Verify hard nproc in $LIMITSCONF" {
  run bash -c "grep '^* hard nproc 150$' $LIMITSCONF"
  [ "$status" -eq 0 ]
}

#adduser

@test "Verify DSHELL in $ADDUSER" {
  run bash -c "grep '^DSHELL=/bin/false$' $ADDUSER"
  [ "$status" -eq 0 ]
}

@test "Verify SHELL in $USERADD" {
  run bash -c "grep '^SHELL=/bin/false$' $USERADD"
  [ "$status" -eq 0 ]
}

@test "Verify INACTIVE in $USERADD" {
  run bash -c "grep '^INACTIVE=35$' $USERADD"
  [ "$status" -eq 0 ]
}

#rootaccess

@test "Verify root in $SECURITYACCESS" {
  run bash -c "grep '^+ : root : 127.0.0.1$' $SECURITYACCESS"
  [ "$status" -eq 0 ]
}

@test "Verify console in /etc/securetty" {
  run oneEntry console /etc/securetty 1
  [ "$status" -eq 0 ]
}


#sshd

@test "Ensure that ssh_host_dsa_key isn't present in $SSHDFILE " {
  run bash -c "grep ssh_host_dsa_key $SSHDFILE"
  [ "$status" -eq 1 ]
}

@test "Verify that X11Forwarding is disabled in $SSHDFILE " {
  run bash -c "grep '^X11Forwarding no$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify LoginGraceTime in $SSHDFILE " {
  run bash -c "grep '^LoginGraceTime 20$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify PermitRootLogin in $SSHDFILE " {
  run bash -c "grep '^PermitRootLogin no$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify KeyRegenerationInterval in $SSHDFILE " {
  run bash -c "grep '^KeyRegenerationInterval 1800$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify UsePrivilegeSeparation in $SSHDFILE " {
  run bash -c "grep '^UsePrivilegeSeparation sandbox$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify LogLevel in $SSHDFILE " {
  run bash -c "grep '^LogLevel VERBOSE$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify UseLogin in $SSHDFILE " {
  run bash -c "grep '^UseLogin no$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify banner in $SSHDFILE " {
  run bash -c "grep '^Banner /etc/issue.net$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify sftp in $SSHDFILE " {
  run bash -c "grep '^Subsystem sftp /usr/lib/ssh/sftp-server -f AUTHPRIV -l INFO$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify MaxAuthTries in $SSHDFILE " {
  run bash -c "grep '^MaxAuthTries 4$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify ClientAliveInterval in $SSHDFILE " {
  run bash -c "grep '^ClientAliveInterval 300$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify ClientAliveCountMax in $SSHDFILE " {
  run bash -c "grep '^ClientAliveCountMax 0$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify PermitUserEnvironment in $SSHDFILE " {
  run bash -c "grep '^PermitUserEnvironment no$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify KexAlgorithms in $SSHDFILE " {
  run bash -c "grep '^KexAlgorithms curve25519-sha256@libssh.org' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify Ciphers in $SSHDFILE " {
  run bash -c "grep '^Ciphers chacha20-poly1305@openssh.com' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify Macs in $SSHDFILE " {
  run bash -c "grep '^Macs hmac-sha2-512-etm@openssh.com' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify MaxSessions in $SSHDFILE " {
  run bash -c "grep '^MaxSessions 2$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

@test "Verify UseDNS in $SSHDFILE " {
  run bash -c "grep '^UseDNS yes$' $SSHDFILE"
  [ "$status" -eq 0 ]
}

#Password

@test "Verify password minimum length in $COMMONPASSWD" {
  run bash -c "grep '^password.*required.*pam_cracklib.*[[:space:]]minlen=15' $COMMONPASSWD"
  [ "$status" -eq 0 ]
}

@test "Verify password hash in $COMMONPASSWD" {
  run bash -c "grep '^password.*pam_unix.*[[:space:]]sha512' $COMMONPASSWD"
  [ "$status" -eq 0 ]
}

@test "Verify remember in $COMMONPASSWD" {
  run bash -c "grep '^password.*pam_unix.*[[:space:]]remember=24' $COMMONPASSWD"
  [ "$status" -eq 0 ]
}

@test "Ensure nullok isn't used in $COMMONAUTH" {
  run bash -c "grep 'nullok' $COMMONAUTH"
  [ "$status" -eq 1 ]
}

@test "Verify pam_tally is used in $COMMONAUTH" {
  run bash -c "grep '^auth required pam_tally' $COMMONAUTH"
  [ "$status" -eq 0 ]
}

@test "Verify pam_tally denies after 5 tries in $COMMONAUTH" {
  run bash -c "grep '^auth required pam_tally.*[[:space:]]deny=5' $COMMONAUTH"
  [ "$status" -eq 0 ]
}

@test "Verify that failed logins are shown in $PAMLOGIN" {
  run bash -c "grep '^session.*pam_lastlog.*showfailed' $PAMLOGIN"
  [ "$status" -eq 0 ]
}

@test "Verify that failed logins are delayed in $PAMLOGIN" {
  run bash -c "grep '^auth.*pam_faildelay.*delay=4000000' $PAMLOGIN"
  [ "$status" -eq 0 ]
}

#cron

@test "Ensure /etc/cron.deny is removed" {
  run test -f /etc/cron.deny
  [ "$status" -eq 1 ]
}

@test "Ensure /etc/at.deny is removed" {
  run test -f /etc/at.deny
  [ "$status" -eq 1 ]
}

@test "Verify root in /etc/cron.allow" {
  run oneEntry root /etc/cron.allow 1
  [ "$status" -eq 0 ]
}

@test "Verify root in /etc/at.allow" {
  run oneEntry root /etc/at.allow 1
  [ "$status" -eq 0 ]
}

@test "Ensure atd is masked" {
  run isMasked atd.service
  [ "$status" -eq 0 ]
}

@test "Verify cron logging is enabled" {
  run bash -c "grep '^cron.\*.*/var/log/cron.log$' /etc/rsyslog.d/50-default.conf"
  [ "$status" -eq 0 ]
}

#ctrlaltdelete

@test "Ensure ctrl-alt-del is masked" {
  run isMasked ctrl-alt-del.target
  [ "$status" -eq 0 ]
}

#Auditd

@test "Verify that audit is enabled" {
  run bash -c "grep '^GRUB_CMDLINE_LINUX=\".*audit=1.*\"' $DEFAULTGRUB"
  [ "$status" -eq 0 ]
}

@test "Verify auditd is enabled" {
  run systemctl is-enabled auditd.service
  [ "$status" -eq 0 ]
}

@test "Verify /etc/audit/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/audit/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/libaudit.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/libaudit.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/audisp/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/audisp/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/auditctl in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/auditctl -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/auditd in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/auditd -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/apparmor/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/apparmor/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/apparmor.d/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/apparmor.d/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/apparmor_parser in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/apparmor_parser -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/aa-complain in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/aa-complain -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/aa-disable in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/aa-disable -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/aa-enforce in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/aa-enforce -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/systemd/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/systemd/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /bin/systemctl in $AUDITRULES" {
  run bash -c "grep '^-w /bin/systemctl -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /bin/journalctl in $AUDITRULES" {
  run bash -c "grep '^-w /bin/journalctl -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.allow in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.allow -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.deny in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.deny -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.d/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.d/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.daily/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.daily/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.hourly/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.hourly/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.monthly/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.monthly/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/cron.weekly/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/cron.weekly/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/crontab in $AUDITRULES" {
  run bash -c "grep '^-w /etc/crontab -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/group in $AUDITRULES" {
  run bash -c "grep '^-w /etc/group -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/passwd in $AUDITRULES" {
  run bash -c "grep '^-w /etc/passwd -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/bin/passwd in $AUDITRULES" {
  run bash -c "grep '^-w /usr/bin/passwd -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/groupadd in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/groupadd -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/groupmod in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/groupmod -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/addgroup in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/addgroup -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/useradd in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/useradd -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/usermod in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/usermod -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/sbin/adduser in $AUDITRULES" {
  run bash -c "grep '^-w /usr/sbin/adduser -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/insmod in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/insmod -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/rmmod in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/rmmod -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/modprobe in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/modprobe -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/login.defs in $AUDITRULES" {
  run bash -c "grep '^-w /etc/login.defs -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/securetty in $AUDITRULES" {
  run bash -c "grep '^-w /etc/securetty -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/hosts in $AUDITRULES" {
  run bash -c "grep '^-w /etc/hosts -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/network/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/network/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/inittab in $AUDITRULES" {
  run bash -c "grep '^-w /etc/inittab -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/init.d/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/init.d/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/init/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/init/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/ld.so.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/ld.so.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/localtime in $AUDITRULES" {
  run bash -c "grep '^-w /etc/localtime -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/timezone in $AUDITRULES" {
  run bash -c "grep '^-w /etc/timezone -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/sysctl.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/sysctl.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/modprobe.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/modprobe.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/modprobe.d/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/modprobe.d/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/modules in $AUDITRULES" {
  run bash -c "grep '^-w /etc/modules -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/pam.d/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/pam.d/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/security/limits.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/security/limits.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/security/pam_env.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/security/pam_env.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/security/namespace.conf in $AUDITRULES" {
  run bash -c "grep '^-w /etc/security/namespace.conf -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/security/namespace.init in $AUDITRULES" {
  run bash -c "grep '^-w /etc/security/namespace.init -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/aliases in $AUDITRULES" {
  run bash -c "grep '^-w /etc/aliases -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/postfix/ in $AUDITRULES" {
  run bash -c "grep '^-w /etc/postfix/ -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/issue in $AUDITRULES" {
  run bash -c "grep '^-w /etc/issue -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/issue.net in $AUDITRULES" {
  run bash -c "grep '^-w /etc/issue.net -p wa' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /bin/su in $AUDITRULES" {
  run bash -c "grep '^-w /bin/su -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /usr/bin/sudo in $AUDITRULES" {
  run bash -c "grep '^-w /usr/bin/sudo -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /etc/sudoers in $AUDITRULES" {
  run bash -c "grep '^-w /etc/sudoers -p rw' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/shutdown in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/shutdown -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/poweroff in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/poweroff -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/reboot in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/reboot -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

@test "Verify /sbin/halt in $AUDITRULES" {
  run bash -c "grep '^-w /sbin/halt -p x' $AUDITRULES"
  [ "$status" -eq 0 ]
}

#Disablemods
@test "Verify that kernel module bluetooth is disabled" {
  run bash -c "grep 'install bluetooth /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module firewire-core is disabled" {
  run bash -c "grep 'install firewire-core /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module net-pf-31 is disabled" {
  run bash -c "grep 'install net-pf-31 /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module soundcore is disabled" {
  run bash -c "grep 'install soundcore /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module thunderbolt is disabled" {
  run bash -c "grep 'install thunderbolt /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module usb-midi is disabled" {
  run bash -c "grep 'install usb-midi /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

@test "Verify that kernel module usb-storage is disabled" {
  run bash -c "grep 'install usb-storage /bin/true' $DISABLEMOD"
  [ "$status" -eq 0 ]
}

#aide

@test "Verify aide timer is enabled" {
  run systemctl is-enabled aidecheck.timer
  [ "$status" -eq 0 ]
}

#users

@test "Ensure user games is removed" {
  run bash -c "grep '^games' /etc/passwd"
  [ "$status" -eq 1 ]
}

@test "Ensure user gnats is removed" {
  run bash -c "grep '^gnats' /etc/passwd"
  [ "$status" -eq 1 ]
}

@test "Ensure user irc is removed" {
  run bash -c "grep '^irc' /etc/passwd"
  [ "$status" -eq 1 ]
}

@test "Ensure user list is removed" {
  run bash -c "grep '^list' /etc/passwd"
  [ "$status" -eq 1 ]
}

@test "Ensure user news is removed" {
  run bash -c "grep '^news' /etc/passwd"
  [ "$status" -eq 1 ]
}

@test "Ensure user uucp is removed" {
  run bash -c "grep '^uucp' /etc/passwd"
  [ "$status" -eq 1 ]
}

#suid

@test "Ensure /bin/fusermount hasn't SUID/GUID set" {
  run gotSGid /bin/fusermount
  [ "$status" -eq 1 ]
}

@test "Ensure /bin/mount hasn't SUID/GUID set" {
  run gotSGid /bin/mount
  [ "$status" -eq 1 ]
}

@test "Ensure /bin/ping hasn't SUID/GUID set" {
  run gotSGid /bin/ping
  [ "$status" -eq 1 ]
}

@test "Ensure /bin/ping6 hasn't SUID/GUID set" {
  run gotSGid /bin/ping6
  [ "$status" -eq 1 ]
}

@test "Ensure /bin/su hasn't SUID/GUID set" {
  run gotSGid /bin/su
  [ "$status" -eq 1 ]
}

@test "Ensure /bin/umount hasn't SUID/GUID set" {
  run gotSGid /bin/umount
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/bsd-write hasn't SUID/GUID set" {
  run gotSGid /usr/bin/bsd-write
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/chage hasn't SUID/GUID set" {
  run gotSGid /usr/bin/chage
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/chfn hasn't SUID/GUID set" {
  run gotSGid /usr/bin/chfn
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/chsh hasn't SUID/GUID set" {
  run gotSGid /usr/bin/chsh
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/mlocate hasn't SUID/GUID set" {
  run gotSGid /usr/bin/mlocate
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/mtr hasn't SUID/GUID set" {
  run gotSGid /usr/bin/mtr
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/newgrp hasn't SUID/GUID set" {
  run gotSGid /usr/bin/newgrp
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/pkexec hasn't SUID/GUID set" {
  run gotSGid /usr/bin/pkexec
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/traceroute6.iputils hasn't SUID/GUID set" {
  run gotSGid /usr/bin/traceroute6.iputils
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/bin/wall hasn't SUID/GUID set" {
  run gotSGid /usr/bin/wall
  [ "$status" -eq 1 ]
}

@test "Ensure /usr/sbin/pppd hasn't SUID/GUID set" {
  run gotSGid /usr/sbin/pppd
  [ "$status" -eq 1 ]
}

#unamsk
@test "Verify umask in /etc/init.d/rc" {
  run bash -c "grep '^umask 027$' /etc/init.d/rc"
  [ "$status" -eq 0 ]
}

@test "Verify umask in /etc/profile" {
  run bash -c "grep '^umask 027$' /etc/profile"
  [ "$status" -eq 0 ]
}

@test "Verify umask in /etc/bash.bashrc" {
  run bash -c "grep '^umask 027$' /etc/bash.bashrc"
  [ "$status" -eq 0 ]
}

#logindefs

@test "Verify KillUserProcesses in $LOGINDCONF" {
  run bash -c "grep '^KillUserProcesses=1$' $LOGINDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify KillExcludeUsers in $LOGINDCONF" {
  run bash -c "grep '^KillExcludeUsers=root$' $LOGINDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify IdleAction in $LOGINDCONF" {
  run bash -c "grep '^IdleAction=lock$' $LOGINDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify IdleActionSec in $LOGINDCONF" {
  run bash -c "grep '^IdleActionSec=15min$' $LOGINDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify RemoveIPC in $LOGINDCONF" {
  run bash -c "grep '^RemoveIPC=yes$' $LOGINDCONF"
  [ "$status" -eq 0 ]
}

#resolveconf

@test "Verify a DNS server is set in $RESOLVEDCONF" {
  run bash -c "grep '^DNS=...' $RESOLVEDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify a FallbackDNS server is set in $RESOLVEDCONF" {
  run bash -c "grep '^FallbackDNS=...' $RESOLVEDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that DNSSEC is used in $RESOLVEDCONF" {
  run bash -c "grep '^DNSSEC=...' $RESOLVEDCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that nss-resolve is present in /etc/nsswitch.conf" {
  run bash -c "grep '^hosts:.*files.*resolve' /etc/nsswitch.conf"
  [ "$status" -eq 0 ]
}

# rkhunter

@test "Verify that rkhunter runs daily" {
  run bash -c "grep '^CRON_DAILY_RUN=\"yes\"$' $RKHUNTERCONF"
  [ "$status" -eq 0 ]
}

@test "Verify that rkhunter autogen is enabled" {
  run bash -c "grep '^APT_AUTOGEN=\"yes\"$' $RKHUNTERCONF"
  [ "$status" -eq 0 ]
}

#apport

@test "Verify that apport is disabled in /etc/default/apport" {
  run bash -c "grep '^enabled=0$' /etc/default/apport"
  [ "$status" -eq 0 ]
}

@test "Verify that apport is masked" {
  run isMasked apport.service
  [ "$status" -eq 0 ]
}

#lockroot

@test "Ensure root account is locked" {
  run isLocked root
  [ "$status" -eq 0 ]
}

#coredump

@test "Ensure that there's no coredump storage in $COREDUMPCONF" {
  run bash -c "grep '^Storage=none$' $COREDUMPCONF"
  [ "$status" -eq 0 ]
}

#protectgrub

@test "Verify password protected GRUB" {
  run bash -c "grep '^password_pbkdf2.*grub\.pbkdf2\.sha512\.' /boot/grub/grub.cfg"
  [ "$status" -eq 0 ]
}

#test_helper.bash

source ../ubuntu.cfg

fragmentPath() {
  systemctl show -p FragmentPath "$1" | sed 's/.*=//'
}

isMasked() {
  isMasked=$(systemctl is-enabled "$1")
  if [[ "$isMasked" = "masked" ]]; then
    exit 0
  else
    exit 1
  fi
}

isLocked() {
  isLocked=$(passwd -S "$1" | awk '{print $2}')
  if [[ "$isLocked" = "L" ]]; then
    exit 0
  else
    exit 1
  fi
}

oneEntry() {
  grepWord="$1"
  grepFile="$2"
  maxLines="$3"
  lineCount=$(cat $grepFile | wc -l)

  if [[ $lineCount -gt $maxLines ]]; then
    exit 1
  fi

  grep "$grepWord" "$grepFile"
}

gotSGid() {
  ls -l $1 | awk '{print $1}' | grep -q 's'
}



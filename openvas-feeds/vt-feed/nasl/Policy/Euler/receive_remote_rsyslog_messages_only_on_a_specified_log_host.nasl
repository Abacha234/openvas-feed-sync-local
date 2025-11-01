# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130303");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Receive Remote rsyslog Messages Only on A Specified Log Host");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.9 Receive Remote rsyslog Messages Only on A Specified Log Host (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.9 Receive Remote rsyslog Messages Only on A Specified Log Host (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 4. Log Audit: 4.2 Rsyslog: 4.2.9 Receive Remote rsyslog Messages Only on A Specified Log Host (Recommendation)");

  script_tag(name:"summary", value:"By default, rsyslog does not listen on log messages from a
remote system. Log message listening via TCP is performed in a similar way to log message listening
via UDP, both requiring rsyslog to load a module, that is, the imtcp.so module and the imudp.so
module respectively. The TCP/UDP port to be listened must be specified for both the imtcp.so and
imudp.so modules. Ensure that remote rsyslog messages are received only on the specified log host
for centralized management by the administrator. Ensure that the log server has enough drive space
to store logs reported by all servers in the networking environment.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Receive Remote rsyslog Messages Only on A Specified Log Host";

solution = "Modify /etc/rsyslog.conf or /etc/rsyslog.d/*.conf to receive remote rsyslog messages
and store the messages in different directories based on the client IP address. You can specify the
directories as required:

1. Restore the TCP configuration:

# vim /etc/rsyslog.conf
$ModLoad imtcp
$InputTCPServerRun 11514
$template Remote, <quote>/var/log/syslog/%fromhost-ip%/%$YEAR%-%$MONTH%-%$DAY%.log<quote>

2. Restore the UDP configuration:

# vim /etc/rsyslog.conf
$ModLoad imudp
$InputUDPServerRun 11514
$template Remote, <quote>/var/log/syslog/%fromhost-ip%/%$YEAR%-%$MONTH%-%$DAY%.log<quote>

3. Run the following command to restart the service for the configuration to take effect:

# systemctl restart rsyslog.service";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -Eh \'^\\$ModLoad.*imtcp|^\\$InputTCPServerRun|^\\$ModLoad.*imudp|^\\$InputUDPServerRun\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null';

expected_value = 'The output should contain "$ModLoad imtcp" and contain "$ModLoad imudp" and contain "$InputTCPServerRun" and contain "$InputUDPServerRun"';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

# ------------------------------------------------------------------
# CHECK : Verify command `grep ^\$ModLoad /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep imtcp`
# ------------------------------------------------------------------

step_cmd = 'grep -Eh \'^\\$ModLoad.*imtcp|^\\$InputTCPServerRun|^\\$ModLoad.*imudp|^\\$InputUDPServerRun\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(strstr(actual_value, '$ModLoad imtcp') && strstr(actual_value, '$ModLoad imudp') && strstr(actual_value, '$InputTCPServerRun') && strstr(actual_value, '$InputUDPServerRun')){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

target = get_kb_item("ssh/login/release_notus");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);

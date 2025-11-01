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
  script_oid("1.3.6.1.4.1.25623.1.0.130363");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Enabling Unnecessary Services and Ports");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.4 Avoid Enabling Unnecessary Services and Ports (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.4 Avoid Enabling Unnecessary Services and Ports (Recommendation)");

  script_tag(name:"summary", value:"In the zones, you need to specify the interfaces, ports, and
services that need to be enabled or disabled. Correct configuration prevents illegitimate packets
from being received and processed, reduces the number of exposed ports on the server, and reduces
the attack surface.

If the configuration is incorrect and the ports or interfaces that should be disabled are enabled,
attackers can exploit them to launch attacks, bringing risks to the server and other NEs.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Avoid Enabling Unnecessary Services and Ports";

solution = "Run the following commands to delete the specified service and port from the specified
region:

# firewall-cmd --zone=work --remove-service samba
success
# firewall-cmd --zone=work --remove-port 80/tcp
success
# firewall-cmd --list-all --zone=work
work (active)
target: default
icmp-block-inversion: no
interfaces: eth1
sources:
services: ssh mdns dhcpv6-client
ports:
protocols:
masquerade: no
forward-ports:
source-ports:
icmp-blocks:
rich rules:

Run the firewall-cmd command to add the current firewall configuration to the configuration file so
that the configuration takes effect permanently.

# firewall-cmd --runtime-to-permanent
success";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# for zone in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v "^[[:space:]]"); do firewall-cmd --list-all --zone=$zone; done';

expected_value = 'The output should contain "public (active)"';

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
# CHECK : Check active zone
# ------------------------------------------------------------------

step_cmd = 'for zone in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v "^[[:space:]]"); do firewall-cmd --list-all --zone=$zone; done';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(strstr(actual_value, 'public (active)')){
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

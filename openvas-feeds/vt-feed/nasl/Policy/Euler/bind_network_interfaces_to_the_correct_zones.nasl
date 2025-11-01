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
  script_oid("1.3.6.1.4.1.25623.1.0.130364");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Bind Network Interfaces to the Correct Zones");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.3 Bind Network Interfaces to the Correct Zones (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.3 Bind Network Interfaces to the Correct Zones (Recommendation)");

  script_tag(name:"summary", value:"Different filtering policies can be configured for different
firewall zones. If the server network is complex and has multiple interfaces that provide different
service functions, it is recommended that interfaces be configured in different zones and different
firewall policies be configured. For example, SSH access is not allowed for external service
interfaces, but the intranet management interface can be accessed through SSH. If all interfaces
are configured in the same zone, varying firewall policies cannot be configured for different
interfaces, which increases the management complexity and reduces the filtering efficiency of
firewall security protection. Due to incorrect configurations, packets that should be rejected may
be received.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Bind Network Interfaces to the Correct Zones";

solution = "Run the firewall-cmd command to remove an interface from a specified zone.

# firewall-cmd --zone=work --remove-interface eth1
success
Run the firewall-cmd command to add an interface to a specified zone.

# firewall-cmd --zone=work --add-interface eth1
success
Run the firewall-cmd command to add the current firewall configuration to the configuration file so
that the configuration takes effect permanently.

# firewall-cmd --runtime-to-permanent
success";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# firewall-cmd --get-active-zones 2>/dev/null';

expected_value = 'The output should not be empty';

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
# CHECK : Check active zones
# ------------------------------------------------------------------

step_cmd = 'firewall-cmd --get-active-zones 2>/dev/null';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(actual_value){
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

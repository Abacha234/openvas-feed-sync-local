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
  script_oid("1.3.6.1.4.1.25623.1.0.130371");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:21 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using Uncommon Network Services");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.1 Avoid Using Uncommon Network Services (Recommendation)");

  script_tag(name:"summary", value:"Some protocols are seldom used and their communities develop
slowly. Therefore, related security issues cannot be quickly resolved. If these protocols are not
disabled, attackers may exploit the protocols or code vulnerabilities to launch attacks.

Stream Control Transmission Protocol (SCTP) is used to transmit multiple data streams between two
ends of a network connection simultaneously. SCTP provides services similar to UDP and TCP.

Transparent Inter-process Communication (TIPC) is used for inter-process communication. It was
originally specially designed for inter-cluster communication. It allows designers to create an
application that can quickly and reliably communicate with other applications without considering
their locations in the cluster environment.

If services such as SCTP and TIPC are not required in service scenarios, disable them in the kernel
to reduce attack scenarios.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Avoid Using Uncommon Network Services";

solution = "In the /etc/modprobe.d/ directory, add a configuration file with a random file name
and the .conf extension, set its owner and owner group to root, and set its permissions to 600.
Enter the following content to disable the SCTP and TIPC protocols:

# vim /etc/modprobe.d/test.conf
install sctp /bin/true
install tipc /bin/true";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# modprobe -n -v sctp

2. Run the command in the terminal:
# modprobe -n -v tipc';

expected_value = '1. The output should contain "install /bin/true" or contain "modprobe: FATAL: Module sctp not found in directory /lib/modules/"
2. The output should contain "install /bin/true" or contain "modprobe: FATAL: Module tipc not found in directory /lib/modules/"';

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

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Verify command `modprobe -n -v sctp`
# ------------------------------------------------------------------

step_cmd_check_1 = 'modprobe -n -v sctp';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'install /bin/true') || strstr(step_res_check_1, 'modprobe: FATAL: Module sctp not found in directory /lib/modules/')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `modprobe -n -v tipc`
# ------------------------------------------------------------------

step_cmd_check_2 = 'modprobe -n -v tipc';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'install /bin/true') || strstr(step_res_check_2, 'modprobe: FATAL: Module tipc not found in directory /lib/modules/')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the some audit check. Please try again.";
}
else if(check_result_1 && check_result_2){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
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

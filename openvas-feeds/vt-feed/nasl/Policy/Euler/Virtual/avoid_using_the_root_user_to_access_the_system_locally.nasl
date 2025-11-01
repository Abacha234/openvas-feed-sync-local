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
  script_oid("1.3.6.1.4.1.25623.1.0.130479");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 12:34:45 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using the root User to Access the System Locally");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/eulerosvirtual");

  script_xref(name:"Policy", value:"EulerOS Virtual: EulerOS Virtual Linux Security Configuration (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.8 Avoid Using the root User to Access the System Locally (Recommendation)");

  script_tag(name:"summary", value:"Users with the root permission can access all Linux resources.
If the root user is used to log in to the Linux OS to perform operations, there are many potential
security risks. To avoid the risks, do not use the root user to log in to the Linux OS. If
necessary, indirectly use the root user through other technical means (for example, run the sudo or
su command).

The root user has the highest permission. Therefore, logging in to the system as the root user
poses the following risks:

1. High-risk misoperations may cause server breakdown, for example, deleting or modifying key
system files by mistake.
2. If multiple users need to perform operations as the root user, the password of the root user is
kept by multiple users, which may cause password leakage and increase password maintenance costs.

By default, using the root user for local login is not configured in openEuler. If the root user is
not required for local login in actual scenarios, you are advised to disable the root user for
local login.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Avoid Using the root User to Access the System Locally";

solution = "1. Add the pam_access.so module of the user type to the /etc/pam.d/system-auth file,
and load the module before the sufficient control line.

# vim /etc/pam.d/system-auth
.
user required pam_unix.so
user required pam_faillock.so
user required pam_access.so
user sufficient pam_localuser.so
.

2. Prevent the root user from logging in to tty1 by setting the /etc/security/access.conf file.

# vim /etc/security/access.conf
-:root:tty1";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# awk \'\\$1~/^account\\$/&&/pam_access\\\\.so/{u=NR} \\$1~/^account\\$/&&/sufficient/&&!s{s=NR} END{exit (u&&s&&u<s)?0:1}\' /etc/pam.d/system-auth && echo PASS || echo FAIL

2. Run the command in the terminal:
# grep "^-:root" /etc/security/access.conf';

expected_value = '1. The output should be equal to "PASS"
2. The output should not be empty';

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
# CHECK 1 :  /etc/pam.d/system-auth must contain pam_access.so before any sufficient line
# ------------------------------------------------------------------

step_cmd_check_1 = 'awk \'\\$1~/^account\\$/&&/pam_access\\\\.so/{u=NR} \\$1~/^account\\$/&&/sufficient/&&!s{s=NR} END{exit (u&&s&&u<s)?0:1}\' /etc/pam.d/system-auth && echo PASS || echo FAIL';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'PASS'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  /etc/security/access.conf must restrict root
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep "^-:root" /etc/security/access.conf';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2){
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

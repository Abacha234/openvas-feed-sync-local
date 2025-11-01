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
  script_oid("1.3.6.1.4.1.25623.1.0.130475");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 12:21:46 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the su Command Is Restricted");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/eulerosvirtual");

  script_xref(name:"Policy", value:"EulerOS Virtual: EulerOS Virtual Linux Security Configuration (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.3 Ensure That the su Command Is Restricted (Requirement)");

  script_tag(name:"summary", value:"The su command enables a common user to have the permissions of
the superuser or other users. It is often used for switching the user from a common user to the
root user. The su command provides a convenient way for users to change their identities. However,
if the su command is run without restrictions, the system may be exposed to potential risks.
Therefore, only a few users are authorized to run the su command to get the permission of the root
user. This improves the security of system users.

openEuler allows only common users in the wheel group to use the su command.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the su Command Is Restricted";

solution = "Modify the /etc/pam.d/su configuration file to prohibit users not in the wheel group
from running the su command.

# vim /etc/pam.d/su
auth required pam_wheel.so use_uid";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -E "^auth\\s+required\\s+pam_wheel.so\\s+use_uid" /etc/pam.d/su';

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
# CHECK : Verify command grep -E "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su
# ------------------------------------------------------------------

step_cmd = 'grep -E "^auth\\s+required\\s+pam_wheel.so\\s+use_uid" /etc/pam.d/su';
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

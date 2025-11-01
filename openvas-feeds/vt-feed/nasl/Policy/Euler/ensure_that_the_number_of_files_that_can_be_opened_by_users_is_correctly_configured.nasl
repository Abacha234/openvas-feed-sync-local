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
  script_oid("1.3.6.1.4.1.25623.1.0.130429");
  script_version("2025-10-31T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-10-31 15:42:05 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler");

  script_add_preference(name:"Soft Limit", type:"entry", value:"1024", id:1);
  script_add_preference(name:"Hard Limit", type:"entry", value:"524288", id:2);

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");

  script_tag(name:"summary", value:"The number of files that can be opened in Linux is limited.
Once the limit is reached by a user, other users can no longer open files.
By default, openEuler limits the maximum number of file handles that can be opened by each user to
1024. If the value exceeds 1024, new file handles cannot be opened. Users can change the limit for
the current session to a value no more than the hard limit set by the administrator (524288 by
default). The root user can change the limit to any value. The limit should be set properly based
on services to prevent a user from opening too many file handles and exhausting system resources.
You can run the ulimit command with the following options to set the limit:

1. Hn: Checks or sets the maximum value of the limit. In a common user session, the limit can only
be lowered once it is set. For example, if the value is set to 3000 (no more than the maximum value
524288 set by the administrator), the limit can only be set to a value less than or equal to 3000
later.

2. -Sn: Checks or sets the current limit. The value is used to limit the number of opened handles.
The limit can be increased or decreased, but cannot exceed the limit specified by -Hn.

Common users can set the limit only for the current session.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

soft_limit = script_get_preference("Soft Limit");
hard_limit = script_get_preference("Hard Limit");

title = "Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured";

solution = "1. The /etc/security/limits.conf file can be used to configure the default limit and
maximum limit for each user. For example, add the following lines:

username hard nofile 10000
username soft nofile 2000

2. Run the ulimit command to set the limit for a session.

Set the limit to 2000 as a common user:
ulimit -Sn 2000
Set the maximum value of the limit to 5000 (no more than the previous maximum value) as a common
user:
ulimit -Hn 5000
Set both the limit and the maximum value of the limit:
ulimit -n 3000

For the root user, the setting method is the same. However, the root user can set the maximum value
of the limit to a value greater than the default value 524288 in openEuler.

# ulimit -Hn 1000000
# ulimit -Hn
1000000";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# ulimit -Sn

2. Run the command in the terminal:
# ulimit -Hn';

expected_value = '1. The output should be equal to "'+soft_limit+'" and be less than to "'+hard_limit+'"
2. The output should be equal to "'+hard_limit+'"';

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
# CHECK 1 :  Check the soft limit
# ------------------------------------------------------------------

step_cmd_check_1 = 'ulimit -Sn';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'soft_limit' && int(step_res_check_1) < int(hard_limit)){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check the hard limit
# ------------------------------------------------------------------

step_cmd_check_2 = 'ulimit -Hn';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'hard_limit'){
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

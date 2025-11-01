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
  script_oid("1.3.6.1.4.1.25623.1.0.130352");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Start the cron Daemon Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.2 Start the cron Daemon Properly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.2 Start the cron Daemon Properly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.2 Start the cron Daemon Properly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.4 Scheduled Tasks: 3.4.2 Start the cron Daemon Properly (Requirement)");

  script_tag(name:"summary", value:"The cron daemon is used to execute batch processing jobs on the
system.

Even if the OS does not have user jobs that need to be run, some system jobs need to be run,
including important jobs such as security monitoring. The cron daemon is used to execute these
jobs. If the cron daemon is not started properly, the impact is as follows:

1. Scheduled tasks configured in cron cannot run automatically. As a result, some planned tasks,
such as log clearing, backup, and system maintenance, may not be executed on time.

2. Scheduled tasks may be delayed. This may affect the normal running and performance of certain
tasks in the system.

3. System maintenance and automation are blocked. Automation tasks are used to monitor the system
status and application running status. If these tasks are not executed on time, potential system
issues may not be detected and handled.

4. Log analysis is affected. Many system administrators use scheduled tasks to perform tasks such
as log analysis and report generation. If these tasks cannot run, important insights into system
running may be missed.

5. Backup maybe delayed. Many backup tasks are scheduled tasks. If the scheduled tasks are not run,
data backup may be delayed or data backed up may be incomplete.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Start the cron Daemon Properly";

solution = "Run the following command to start the cron daemon:

# systemctl --now enable crond";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# systemctl is-enabled crond

2. Run the command in the terminal:
# systemctl is-active crond';

expected_value = '1. The output should be equal to "enabled"
2. The output should be equal to "active"';

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
# CHECK 1 :  Ensure That crond Is Enabled
# ------------------------------------------------------------------

step_cmd_check_1 = 'systemctl is-enabled crond';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'enabled'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Ensure That crond Is Active
# ------------------------------------------------------------------

step_cmd_check_2 = 'systemctl is-active crond';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'active'){
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

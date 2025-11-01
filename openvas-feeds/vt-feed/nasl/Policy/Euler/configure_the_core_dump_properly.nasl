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
  script_oid("1.3.6.1.4.1.25623.1.0.130338");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure the Core Dump Properly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.20 Configure the Core Dump Properly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.20 Configure the Core Dump Properly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.20 Configure the Core Dump Properly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.5 Kernel: 3.5.20 Configure the Core Dump Properly (Requirement)");

  script_tag(name:"summary", value:"A core dump records the memory status when a program stops
abnormally or breaks down. It helps locate faults but may contain sensitive information in the
process memory. In some cases, the core dump function needs to be enabled to record problem causes.
When enabling the core dump function, restrict the log input path and the users who can access the
path.
Enabling the core dump function helps locate the fault that causes a program to stop abnormally or
break down, but sensitive information in the memory may be disclosed. This function is enabled by
default in openEuler. You need to disable the function or restrict the log input path and access
users as required.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Configure the Core Dump Properly";

solution = 'Method for disabling the function:

1. Run the following command to disable the system from generating core dumps for the current
session:

# ulimit -c 0

2. Open the /etc/security/limits.conf file, add or modify the configuration, and make it take
effect permanently.

* hard core 0

Method of restricting the function:

1. Set ulimit -c to any value except 0. For example:

# ulimit -c 10485760

2. Set the path for storing core dumps and the file name format. Open the
/proc/sys/kernel/core_pattern file and configure the storage location and name format of core
dumps. In the following example, all core dumps are generated in the /corefiles directory (absolute
path). The file name format is core-command_name-pid-timestamp.

# sysctl "kernel.core_pattern=/corefiles/core-%e-%p-%t"

Open the /etc/sysctl.conf file and add or modify the following configuration:

kernel.core_pattern=/corefiles/core-%e-%p-%t

You are advised to create an independent partition for /corefiles to prevent the directory from
occupying the system or service partition. This prevents the partition from being exhausted due to
excessive core dumps and thus affecting system or service running.

3. Restrict the directory access permission. Restrict the scope of users who can access the
directory as required.

3.1 Restrict the access of a single user (for example, admin).

# chown admin /corefiles
# chmod 700 /corefiles

3.2 Use the sticky bit protection technology to restrict the access of users in the same group (for
example, core_group).

# chown root:core_group /corefiles
# chmod 1770 /corefiles

3.3 Use the sticky bit protection technology to restrict the access of all users.

# chown root:root /corefiles
# chmod 1777 /corefiles

Note: The sticky bit does not allow user A to access user B\'s files in the directory unless user
B\'s file permission allows user A to access the files.

4. You are advised to disable the setuid application from generating core dumps. Run the following
command to disable the setuid application from generating core dumps:
# sysctl -w "fs.suid_dumpable=0"
Open the /etc/sysctl.conf file, add or modify the configuration, and make it take effect
permanently.
fs.suid_dumpable=0';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# ulimit -c

2. Run the command in the terminal:
# core_path=$(sysctl kernel.core_pattern | awk -F"^[[:space:]]*kernel.core_pattern[[:space:]]*=[[:space:]]*" \'{print \\$2}\'); [[ "${core_path}" =~ ^/.+ ]] || { echo "kernel.core_pattern[${core_path}] must be started with /"; exit 1; }; core_dir=$(dirname "${core_path}"); [[ -d "${core_dir}" ]] || { echo "kernel.core_pattern dir[${core_dir}] not exist"; exit 1; }; rights_digit=$(stat -c %a "${core_dir}"); [[ "${rights_digit}" =~ ^700$|^1770$|^1777$ ]] || { echo "rights[${rights_digit}] of dir[${core_dir}] not safe, must be 700 or 1770 or 1777"; exit 1; }; exit 0

3. Run the command in the terminal:
# grep -E \'^\\s*[^#\\s]+\\s+hard\\s+core\\s+0\' /etc/security/limits.conf';

expected_value = '1. The output should be equal to "0"
2. The output should be empty
3. The output should not be empty';

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
# CHECK 1 :  Verify command `ulimit -c`
# ------------------------------------------------------------------

step_cmd_check_1 = 'ulimit -c';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == '0'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify the command for restrictions
# ------------------------------------------------------------------

step_cmd_check_2 = 'core_path=$(sysctl kernel.core_pattern | awk -F"^[[:space:]]*kernel.core_pattern[[:space:]]*=[[:space:]]*" \'{print \\$2}\'); [[ "${core_path}" =~ ^/.+ ]] || { echo "kernel.core_pattern[${core_path}] must be started with /"; exit 1; }; core_dir=$(dirname "${core_path}"); [[ -d "${core_dir}" ]] || { echo "kernel.core_pattern dir[${core_dir}] not exist"; exit 1; }; rights_digit=$(stat -c %a "${core_dir}"); [[ "${rights_digit}" =~ ^700$|^1770$|^1777$ ]] || { echo "rights[${rights_digit}] of dir[${core_dir}] not safe, must be 700 or 1770 or 1777"; exit 1; }; exit 0';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify command `grep -E \'^\\s*[^#\\s]+\\s+hard\\s+core\\s+0\' /etc/security/limits.conf`
# ------------------------------------------------------------------

step_cmd_check_3 = 'grep -E \'^\\s*[^#\\s]+\\s+hard\\s+core\\s+0\' /etc/security/limits.conf';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(step_res_check_3){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the some audit check. Please try again.";
}
else if(check_result_1 || check_result_2 || check_result_3){
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

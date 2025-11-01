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
  script_oid("1.3.6.1.4.1.25623.1.0.130391");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable AIDE");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.2 Enable AIDE (Recommendation)");

  script_tag(name:"summary", value:"Advanced intrusion detection environment (AIDE) is an intrusion
detection tool that checks the integrity of system files and directories and identifies those
maliciously tampered with. In principle, the integrity check can be performed only after an AIDE
benchmark database is constructed, which contains some attributes of files or directories, such as
permissions and users. The system compares the current system status with the benchmark database to
obtain the integrity check result, and then reports the check report recording the file or
directory changes of the current system.
With AIDE enabled, the system can effectively identify malicious file or directory tampering,
improving system integrity and security. The files or directories to be checked can be configured
flexibly. You only need to query the check report to determine whether malicious tampering occurs.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Enable AIDE";

solution = "1. If AIDE is not installed, run the yum or dnf command to install the software
package.

yum install aide
Or
dnf install aide

2. Configure the files or directories to be monitored in the /etc/aide.conf configuration file. By
default, some directories to be monitored are configured in the /etc/aide.conf file, including
important directories such as /boot, /bin, /lib, and /lib64. Add files or directories to be
monitored as required.

# vim /etc/aide.conf
/boot NORMAL
/bin NORMAL
/lib NORMAL
/lib64 NORMAL

3. Generate the benchmark database. After the initialization command is executed, the
aide.db.new.gz file is generated in the /var/lib/aide directory. Rename the file as aide.db.gz,
which is the benchmark database.

# aide --init
# mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
4. Run the following aide --check<semicolon> command to perform the intrusion check. The check
result is displayed on the screen and saved to the /var/log/aide/aide.log file.

# aide --check

5. Update the benchmark database.

# aide --update
# mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# aide --version | grep -i "^AIDE [0-9]*\\.[0-9]*"

2. Run the command in the terminal:
# grep -E "^/[^ ]+\\s+NORMAL$" /etc/aide.conf

3. Run the command in the terminal:
# ls /var/lib/aide/aide.db.gz';

expected_value = '1. The output should not be empty
2. The output should not be empty
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
# CHECK 1 :  Verify command `aide --version | grep -i "^AIDE [0-9]*\\.[0-9]*"`
# ------------------------------------------------------------------

step_cmd_check_1 = 'aide --version | grep -i "^AIDE [0-9]*\\.[0-9]*"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `grep -E "^/[^ ]+\\s+NORMAL$" /etc/aide.conf`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -E "^/[^ ]+\\s+NORMAL$" /etc/aide.conf';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Verify command `ls /var/lib/aide/aide.db.gz`
# ------------------------------------------------------------------

step_cmd_check_3 = 'ls /var/lib/aide/aide.db.gz';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(step_res_check_3){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(eregmatch(string: actual_value, pattern:"(Permission denied|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the some audit check. Please try again.";
}
else if(eregmatch(string: actual_value, pattern:"(No such file or directory|Command not found)", icase: TRUE)){
  compliant = "no";
  comment = "One or more checks failed";
}
else if(check_result_1 && check_result_2 && check_result_3){
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

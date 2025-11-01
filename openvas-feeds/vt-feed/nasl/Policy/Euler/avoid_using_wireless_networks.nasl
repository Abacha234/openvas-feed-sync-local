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
  script_oid("1.3.6.1.4.1.25623.1.0.130370");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:21 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using Wireless Networks");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler");

  script_add_preference(name:"wifi", type:"entry", value:"no;yes", id:1);
  script_add_preference(name:"wwan", type:"entry", value:"no;yes", id:2);

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.2 Avoid Using Wireless Networks (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 3. Running and Services: 3.1 Network: 3.1.2 Avoid Using Wireless Networks (Recommendation)");

  script_tag(name:"summary", value:"If the hardware device contains wireless modules such as Wi-Fi
and Wi-Fi is enabled in the system, the server may connect to the network wirelessly. If the
connection is not managed, the network may be unstable and the attack surface increases.

If no wireless network is used, you are advised to disable the wireless network function as
required.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

wifi = script_get_preference("wifi");
wwan = script_get_preference("wwan");

title = "Avoid Using Wireless Networks";

solution = "Run the nmcli command to permanently disable Wi-Fi and WWAN. They remain disabled even
if the system is restarted.

# nmcli radio all off
# nmcli radio all
WIFI-HW WIFI WWAN-HW WWAN
enabled disabled enabled disabled";

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# nmcli --colors no radio wifi

2. Run the command in the terminal:
# nmcli --colors no radio wwan';

expected_value = '1. The output should be equal to "disabled" or be empty
2. The output should be equal to "disabled" or be empty';

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
# CHECK 1 :  Check WIFI
# ------------------------------------------------------------------

step_cmd_check_1 = 'nmcli --colors no radio wifi';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'disabled' || step_res_check_1 == 'yes'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check  WWAN
# ------------------------------------------------------------------

step_cmd_check_2 = 'nmcli --colors no radio wwan';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2 == 'disabled' || step_res_check_2 == 'yes'){
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

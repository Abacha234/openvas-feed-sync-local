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
  script_oid("1.3.6.1.4.1.25623.1.0.130492");
  script_version("2025-09-29T10:42:25+0000");
  script_tag(name:"last_modification", value:"2025-09-29 10:42:25 +0000 (Mon, 29 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 13:15:42 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Preset known_hosts for the SSH Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "ssh/login/eulerosvirtual");

  script_xref(name:"Policy", value:"EulerOS Virtual: EulerOS Virtual Linux Security Configuration (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.18 Do Not Preset known_hosts for the SSH Service (Recommendation)");

  script_tag(name:"summary", value:"known_hosts stores the public keys of the computers that the
host has accessed. After a user successfully logs in to another computer, the public key
information is automatically saved in $HOME/.ssh/known_hosts. When the same computer is accessed
next time, its public key is verified. If the verification fails, the connection is rejected.
Therefore, known_hosts cannot be preset in the system.

When known_hosts is preset in the system:

1. If the public key of the target host is verified successfully, no alarm is generated during the
connection to the target host, which increases security risks.
2. If the public key of the target host fails to be verified, the connection to the target host
cannot be established.

By default, known_hosts is not preset in openEuler.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Preset known_hosts for the SSH Service";

solution = "Delete the detected file, for example, the /root/.ssh/known_hosts file.

# rm /root/.ssh/known_hosts";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# find /home/ /root/ -name known_hosts';

expected_value = 'The output should be empty';

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
# CHECK : Verify command `find /home/ /root/ -name known_hosts`
# ------------------------------------------------------------------

step_cmd = 'find /home/ /root/ -name known_hosts';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(strstr(actual_value,"syntax error near unexpected token") || strstr(actual_value,"Permission denied")){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(!actual_value){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);

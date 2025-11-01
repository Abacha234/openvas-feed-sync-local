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
  script_oid("1.3.6.1.4.1.25623.1.0.130493");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 13:17:18 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Configure Deprecated Options for the SSH Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/eulerosvirtual");

  script_xref(name:"Policy", value:"EulerOS Virtual: EulerOS Virtual Linux Security Configuration (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.19 Do Not Configure Deprecated Options for the SSH Service (Recommendation)");

  script_tag(name:"summary", value:"Currently, the SSH service communication protocols are
classified into the first generation and the second generation. The configuration options of the
SSH service of different versions are incompatible. In addition, the configuration options of some
earlier versions are deprecated in the new version. The configuration file of the SSH server is
stored in /etc/ssh/sshd_config. The current configuration options are those of the
second-generation SSH communication protocol. If you forcibly configure the configuration options
of an earlier version, an error is reported during the self-check of the SSH service, and the
configuration options do not take effect. Therefore, do not configure deprecated SSH options.

By default, deprecated SSH options are not configured in openEuler.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Do Not Configure Deprecated Options for the SSH Service";

solution = "Edit the SSH service configuration file, delete the deprecated configuration options,
and restart the sshd service.

# vim /etc/ssh/sshd_config

# RSAAuthentication yes
# RhostsRSAAuthentication no

# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# sshd -t';

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
# CHECK : Verify command `sshd -t`
# ------------------------------------------------------------------

step_cmd = 'sshd -t';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
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

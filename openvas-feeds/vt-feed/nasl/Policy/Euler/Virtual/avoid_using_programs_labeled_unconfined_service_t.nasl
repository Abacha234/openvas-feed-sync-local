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
  script_oid("1.3.6.1.4.1.25623.1.0.130480");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-09-25 12:37:22 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using Programs Labeled unconfined_service_t");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/eulerosvirtual");

  script_xref(name:"Policy", value:"EulerOS Virtual: EulerOS Virtual Linux Security Configuration (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.9 Avoid Using Programs Labeled unconfined_service_t (Recommendation)");

  script_tag(name:"summary", value:"The purpose of setting the unconfined_service_t label for
SELinux is to enable some third-party service processes not configured with SELinux policies to run
without restrictions. By default, when systemd runs a third-party application whose label is bin_t
or usr_t (generally located in directories such as /usr/bin and /opt), the generated process label
is unconfined_service_t.

Different from other high-permission labels (such as unconfined_t and initrc_t),
unconfined_service_t has only a few domain conversion rules. This means that even if the process
runs applications that have been configured with SELinux policies, the label of the new process is
still unconfined_service_t, and the SELinux policy configured for the process does not take effect.
If the process is attacked, the system will be greatly affected.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Avoid Using Programs Labeled unconfined_service_t";

solution = "Configure a proper SELinux policy for the application and add a domain conversion rule
so that the domain conversion rule is converted to the process label of the configured policy when
being executed.";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# ps -eZ | grep unconfined_service_t';

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
# CHECK : Verify command `ps -eZ | grep unconfined_service_t`
# ------------------------------------------------------------------

step_cmd = 'ps -eZ | grep unconfined_service_t';
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

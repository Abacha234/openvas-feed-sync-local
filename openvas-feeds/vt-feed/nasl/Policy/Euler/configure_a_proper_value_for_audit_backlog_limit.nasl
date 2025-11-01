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
  script_oid("1.3.6.1.4.1.25623.1.0.130289");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:17 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Value for audit_backlog_limit");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/euleros_openeuler");

  script_add_preference(name:"Audit backlog limit value", type:"entry", value:"8192", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: openEuler Security Configuration Baseline (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.9 Configure a Proper Value for audit_backlog_limit (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: openEuler Security Configuration Baseline (v1.0.0): 4. Log Audit: 4.1 Audit: 4.1.9 Configure a Proper Value for audit_backlog_limit (Recommendation)");

  script_tag(name:"summary", value:"audit_backlog_limit sets the buffer queue length for audit
events awaiting transfer to the audit service. The default value is 64. If the queue is full, audit
events are discarded and an alarm log is generated, indicating that the queue is full. If the value
is too small, audit events may be lost.

If auditd is enabled during system startup, you are advised to set audit_backlog_limit to a large
value. This is because the auditd service has not started during kernel startup, and all events are
buffered in the queue.

The value of audit_backlog_limit is not configured in openEuler by default. You are advised to
configure the value based on the actual scenario.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

audit_backlog_limit_value = script_get_preference("Audit backlog limit value");

title = "Configure a Proper Value for audit_backlog_limit";

solution = "1. Open the grub.cfg file and add the configuration to the end of the corresponding
kernel boot parameter. Note that the directory where the grub.cfg file is located varies according
to the system installation configuration. In most cases, the file exists in the /boot/grub2/ or
/boot/efi/EFI/openeuler/ directory.

# vim /boot/grub2/grub.cfg
linuxefi /vmlinuz- root=/dev/mapper/openeuler-root ro resume=/dev/mapper/openeuler-swap
rd.lvm.lv=openeuler/root rd.lvm.lv=openeuler/swap crashkernel=512M quiet audit=1
audit_backlog_limit=

2. Alternatively, modify the /etc/default/grub configuration file, add audit_backlog_limit= to the
GRUB_CMDLINE_LINUX field, and regenerate the grub.cfg file.

# /etc/default/grub
GRUB_CMDLINE_LINUX=<quote>/dev/mapper/openeuler-swap rd.lvm=openeuler/root rd.lvm.lv=openeuler/swap
crashkernel quiet audit=1 audit_backlog_limit=<quote>

# grub2-mkconfig -o /boot/grub2/grub.cfg

3. Restart the system for the modification to take effect.

# reboot";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# cat /proc/cmdline | grep "audit_backlog_limit"';

expected_value = 'The output should contain "audit_backlog_limit="';

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
# CHECK : Verify command `cat /proc/cmdline | grep "audit_backlog_limit"`
# ------------------------------------------------------------------

step_cmd = 'cat /proc/cmdline | grep "audit_backlog_limit"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(eregmatch(string: actual_value, pattern:"(No such file or directory|Permission denied|Command not found|Segmentation fault|service not found|is not running|syntax error near unexpected token|syntax error: unexpected end of file)", icase: TRUE)){
  compliant = "incomplete";
  comment = "Something went wrong during the audit check. Please try again.";
}else if(TRUE){
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

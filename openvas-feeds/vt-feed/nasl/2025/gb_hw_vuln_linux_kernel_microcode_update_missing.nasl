# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119209");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  # nb: No severity so far due to:
  # - Might not even affected (e.g. Microcode was updated after boot, see insight tag)
  # - Not updated Microcode could just contain functional changes (See "the kernel does not know or
  #   care" below)
  script_tag(name:"creation_date", value:"2025-10-28 10:51:43 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Linux Kernel Old Microcode Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/vulnerable");

  script_xref(name:"URL", value:"https://docs.kernel.org/admin-guide/hw-vuln/old_microcode.html");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files.git");

  script_tag(name:"summary", value:"Checks if the remote host is using old Microcode loaded into the
  Linux Kernel.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the Microcode update
  status reported by the Linux Kernel.");

  script_tag(name:"insight", value:"The kernel keeps a table of released microcode. Systems that had
  microcode older than this at boot will say 'Vulnerable'. This means that the system was vulnerable
  to some known CPU issue. It could be security or functional, the kernel does not know or care.

  Just like all the other hardware vulnerabilities, exposure is determined at boot. Runtime
  microcode updates do not change the status of this vulnerability.");

  script_tag(name:"solution", value:"You should update the CPU microcode to mitigate any exposure.
  This is usually accomplished by updating the files in /lib/firmware/intel-ucode/ via normal
  distribution updates. Intel also distributes these files in a github repo: [link moved to
  references]");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/vulnerable" ) )
  exit( 99 );

covered_vuln = "old_microcode";

if( ! mitigation_status = get_kb_item( "ssh/hw_vulns/kernel_mitigations/vulnerable/" + covered_vuln ) )
  exit( 99 );

# nb: No need to continue with these, we only want to report oudated Microcode and in that case the
# system should report "Vulnerable" (even if not fully correct as the Microcode update might only
# contain functional updates).
if( "sysfs file missing (" >< mitigation_status || "Not affected" >< mitigation_status || "Vulnerable" >!< mitigation_status )
 exit( 99 );

report = 'The Linux Kernel on the remote host is using outdated Microcode as reported by the sysfs interface:\n\n';

path = "/sys/devices/system/cpu/vulnerabilities/" + covered_vuln;
info[path] = mitigation_status;

# nb:
# - Store link between gb_hw_vuln_linux_kernel_mitigation_detect.nasl and this VT
# - We don't want to use get_app_* functions as we're only interested in the cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108765" ); # gb_hw_vuln_linux_kernel_mitigation_detect.nasl
register_host_detail( name:"detected_at", value:"general/tcp" ); # nb: gb_hw_vuln_linux_kernel_mitigation_detect.nasl is using port:0

report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file checked", "Linux Kernel status (SSH response)" ) );
report += '\n\nNotes on the "Linux Kernel status (SSH response)" column:';
report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are reported directly by the Linux Kernel.';
report += '\n- All other strings are responses to various SSH commands.';

log_message( port:0, data:report );
exit( 0 );

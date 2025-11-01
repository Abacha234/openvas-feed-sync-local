# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66954");
  script_cve_id("CVE-2009-3080", "CVE-2009-3726", "CVE-2009-4005", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4536", "CVE-2010-0007", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");
  script_tag(name:"creation_date", value:"2010-02-25 21:02:04 +0000 (Thu, 25 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2003");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2003");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NOTE: This kernel update marks the final planned kernel security update for the 2.6.18 kernel in the Debian release 'etch'. Although security support for 'etch' officially ended on February 15th, 2010, this update was already in preparation before that date. A final update that includes fixes for these issues in the 2.6.24 kernel is also in preparation and will be released shortly.

Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3080

Dave Jones reported an issue in the gdth SCSI driver. A missing check for negative offsets in an ioctl call could be exploited by local users to create a denial of service or potentially gain elevated privileges.

CVE-2009-3726

Trond Myklebust reported an issue where a malicious NFS server could cause a denial of service condition on its clients by returning incorrect attributes during an open call.

CVE-2009-4005

Roel Kluin discovered an issue in the hfc_usb driver, an ISDN driver for Colognechip HFC-S USB chip. A potential read overflow exists which may allow remote users to cause a denial of service condition (oops).

CVE-2009-4020

Amerigo Wang discovered an issue in the HFS filesystem that would allow a denial of service by a local user who has sufficient privileges to mount a specially crafted filesystem.

CVE-2009-4021

Anana V. Avati discovered an issue in the fuse subsystem. If the system is sufficiently low on memory, a local user can cause the kernel to dereference an invalid pointer resulting in a denial of service (oops) and potentially an escalation of privileges.

CVE-2009-4536

Fabian Yamaguchi reported an issue in the e1000 driver for Intel gigabit network adapters which allow remote users to bypass packet filters using specially crafted ethernet frames.

CVE-2010-0007

Florian Westphal reported a lack of capability checking in the ebtables netfilter subsystem. If the ebtables module is loaded, local users can add and modify ebtables rules.

CVE-2010-0410

Sebastian Krahmer discovered an issue in the netlink connector subsystem that permits local users to allocate large amounts of system memory resulting in a denial of service (out of memory).

CVE-2010-0415

Ramon de Carvalho Valle discovered an issue in the sys_move_pages interface, limited to amd64, ia64 and powerpc64 flavors in Debian. Local users can exploit this issue to cause a denial of service (system crash) or gain access to sensitive kernel memory.

CVE-2010-0622

Jerome Marchand reported an issue in the futex subsystem that allows a local user to force an invalid futex state which results in a denial of service (oops).

This update also fixes a regression introduced by a previous security update that caused problems booting on certain s390 systems.

For the oldstable distribution (etch), ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
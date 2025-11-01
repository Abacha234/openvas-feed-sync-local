# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62957");
  script_cve_id("CVE-2008-3527", "CVE-2008-3528", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300");
  script_tag(name:"creation_date", value:"2008-12-23 17:28:16 +0000 (Tue, 23 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1687)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1687");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1687");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1687 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3527

Tavis Ormandy reported a local DoS and potential privilege escalation in the Virtual Dynamic Shared Objects (vDSO) implementation.

CVE-2008-3528

Eugene Teo reported a local DoS issue in the ext2 and ext3 filesystems. Local users who have been granted the privileges necessary to mount a filesystem would be able to craft a corrupted filesystem that causes the kernel to output error messages in an infinite loop.

CVE-2008-4554

Milos Szeredi reported that the usage of splice() on files opened with O_APPEND allows users to write to the file at arbitrary offsets, enabling a bypass of possible assumed semantics of the O_APPEND flag.

CVE-2008-4576

Vlad Yasevich reported an issue in the SCTP subsystem that may allow remote users to cause a local DoS by triggering a kernel oops.

CVE-2008-4933

Eric Sesterhenn reported a local DoS issue in the hfsplus filesystem. Local users who have been granted the privileges necessary to mount a filesystem would be able to craft a corrupted filesystem that causes the kernel to overrun a buffer, resulting in a system oops or memory corruption.

CVE-2008-4934

Eric Sesterhenn reported a local DoS issue in the hfsplus filesystem. Local users who have been granted the privileges necessary to mount a filesystem would be able to craft a corrupted filesystem that results in a kernel oops due to an unchecked return value.

CVE-2008-5025

Eric Sesterhenn reported a local DoS issue in the hfs filesystem. Local users who have been granted the privileges necessary to mount a filesystem would be able to craft a filesystem with a corrupted catalog name length, resulting in a system oops or memory corruption.

CVE-2008-5029

Andrea Bittau reported a DoS issue in the unix socket subsystem that allows a local user to cause memory corruption, resulting in a kernel panic.

CVE-2008-5079

Hugo Dias reported a DoS condition in the ATM subsystem that can be triggered by a local user by calling the svc_listen function twice on the same socket and reading /proc/net/atm/*vc.

CVE-2008-5182

Al Viro reported race conditions in the inotify subsystem that may allow local users to acquire elevated privileges.

CVE-2008-5300

Dann Frazier reported a DoS condition that allows local users to cause the out of memory handler to kill off privileged processes or trigger soft lockups due to a starvation issue in the unix socket subsystem.

For the stable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-23etch1.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.

Note: Debian 'etch' includes linux kernel packages based upon both the 2.6.18 and 2.6.24 linux releases. All known security issues ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
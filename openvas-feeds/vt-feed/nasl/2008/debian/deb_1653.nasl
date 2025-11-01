# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61775");
  script_cve_id("CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302");
  script_tag(name:"creation_date", value:"2008-11-01 00:55:10 +0000 (Sat, 01 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:40:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1653)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1653");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1653");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1653 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6716

Joe Jin reported a local denial of service vulnerability that allows system users to trigger an oops due to an improperly initialized data structure.

CVE-2008-1514

Jan Kratochvil reported a local denial of service vulnerability in the ptrace interface for the s390 architecture. Local users can trigger an invalid pointer dereference, leading to a system panic.

CVE-2008-3276

Eugene Teo reported an integer overflow in the DCCP subsystem that may allow remote attackers to cause a denial of service in the form of a kernel panic.

CVE-2008-3525

Eugene Teo reported a lack of capability checks in the kernel driver for Granch SBNI12 leased line adapters (sbni), allowing local users to perform privileged operations.

CVE-2008-3833

The S_ISUID/S_ISGID bits were not being cleared during an inode splice, which, under certain conditions, can be exploited by local users to obtain the privileges of a group for which they are not a member. Mark Fasheh reported this issue.

CVE-2008-4210

David Watson reported an issue in the open()/creat() system calls which, under certain conditions, can be exploited by local users to obtain the privileges of a group for which they are not a member.

CVE-2008-4302

A coding error in the splice subsystem allows local users to attempt to unlock a page structure that has not been locked, resulting in a system crash.

For the stable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-22etch3.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
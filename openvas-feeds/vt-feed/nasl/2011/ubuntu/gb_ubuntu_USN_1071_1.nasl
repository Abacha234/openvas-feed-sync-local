# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840595");
  script_cve_id("CVE-2010-3086", "CVE-2010-3859", "CVE-2010-3873", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4078", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160");
  script_tag(name:"creation_date", value:"2011-02-28 15:24:14 +0000 (Mon, 28 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1071-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1071-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.15' package(s) announced via the USN-1071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that the Linux kernel did not properly implement
exception fixup. A local attacker could exploit this to crash the kernel,
leading to a denial of service. (CVE-2010-3086)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
not correctly clear kernel memory. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets implementation
did not properly initialize certain structures. A local attacker could
exploit this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3876)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
properly audit certain bytecodes in netlink messages. A local attacker
could exploit this to cause the kernel to hang, leading to a denial of
service. (CVE-2010-3880)

Dan Rosenberg discovered that the SiS video driver did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4078)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface driver
did not correctly clear kernel memory. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy. (CVE-2010-4080,
CVE-2010-4081)

Dan Rosenberg discovered that the semctl syscall did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4083)

James Bottomley discovered that the ICP vortex storage array controller
driver did not validate certain sizes. A local attacker on a 64bit system
could exploit this to crash the kernel, leading to a denial of service.
(CVE-2010-4157)

Dan Rosenberg discovered that the Linux kernel L2TP implementation
contained multiple integer signedness errors. A local attacker could
exploit this to crash the kernel, or possibly gain root privileges.
(CVE-2010-4160)");

  script_tag(name:"affected", value:"'linux-source-2.6.15' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

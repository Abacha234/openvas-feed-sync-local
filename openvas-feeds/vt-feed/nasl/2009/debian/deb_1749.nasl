# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63681");
  script_cve_id("CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1749)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1749");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1749");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1749 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0029

Christian Borntraeger discovered an issue effecting the alpha, mips, powerpc, s390 and sparc64 architectures that allows local users to cause a denial of service or potentially gain elevated privileges.

CVE-2009-0031

Vegard Nossum discovered a memory leak in the keyctl subsystem that allows local users to cause a denial of service by consuming all of kernel memory.

CVE-2009-0065

Wei Yongjun discovered a memory overflow in the SCTP implementation that can be triggered by remote users.

CVE-2009-0269

Duane Griffin provided a fix for an issue in the eCryptfs subsystem which allows local users to cause a denial of service (fault or memory corruption).

CVE-2009-0322

Pavel Roskin provided a fix for an issue in the dell_rbu driver that allows a local user to cause a denial of service (oops) by reading 0 bytes from a sysfs entry.

CVE-2009-0676

Clement LECIGNE discovered a bug in the sock_getsockopt function that may result in leaking sensitive kernel memory.

CVE-2009-0675

Roel Kluin discovered inverted logic in the skfddi driver that permits local, unprivileged users to reset the driver statistics.

CVE-2009-0745

Peter Kerwien discovered an issue in the ext4 filesystem that allows local users to cause a denial of service (kernel oops) during a resize operation.

CVE-2009-0746

Sami Liedes reported an issue in the ext4 filesystem that allows local users to cause a denial of service (kernel oops) when accessing a specially crafted corrupt filesystem.

CVE-2009-0747

David Maciejak reported an issue in the ext4 filesystem that allows local users to cause a denial of service (kernel oops) when mounting a specially crafted corrupt filesystem.

CVE-2009-0748

David Maciejak reported an additional issue in the ext4 filesystem that allows local users to cause a denial of service (kernel oops) when mounting a specially crafted corrupt filesystem.

For the oldstable distribution (etch), these problems, where applicable, will be fixed in future updates to linux-2.6 and linux-2.6.24.

For the stable distribution (lenny), these problems have been fixed in version 2.6.26-13lenny2.

We recommend that you upgrade your linux-2.6 packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
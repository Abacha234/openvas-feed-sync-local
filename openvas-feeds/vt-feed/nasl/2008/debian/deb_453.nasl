# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53681");
  script_cve_id("CVE-2004-0077");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-453)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-453");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-453");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-2.2.20-amiga, kernel-image-2.2.20-atari, kernel-image-2.2.20-bvme6000, kernel-image-2.2.20-i386, kernel-image-2.2.20-mac, kernel-image-2.2.20-mvme16x, kernel-image-2.2.20-mvme147, kernel-image-2.2.20-reiserfs-i386, kernel-patch-2.2.20-powerpc, kernel-source-2.2.20' package(s) announced via the DSA-453 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Starzetz and Wojciech Purczynski of isec.pl discovered a critical security vulnerability in the memory management code of Linux inside the mremap(2) system call. Due to flushing the TLB (Translation Lookaside Buffer, an address cache) too early it is possible for an attacker to trigger a local root exploit.

The attack vectors for 2.4.x and 2.2.x kernels are exclusive for the respective kernel series, though. We formerly believed that the exploitable vulnerability in 2.4.x does not exist in 2.2.x which is still true. However, it turned out that a second (sort of) vulnerability is indeed exploitable in 2.2.x, but not in 2.4.x, with a different exploit, of course.

For the stable distribution (woody) this problem has been fixed in the following versions and architectures:

package

arch

version

kernel-source-2.2.20

source

2.2.20-5woody3

kernel-image-2.2.20-i386

i386

2.2.20-5woody5

kernel-image-2.2.20-reiserfs-i386

i386

2.2.20-4woody1

kernel-image-2.2.20-amiga

m68k

2.20-4

kernel-image-2.2.20-atari

m68k

2.2.20-3

kernel-image-2.2.20-bvme6000

m68k

2.2.20-3

kernel-image-2.2.20-mac

m68k

2.2.20-3

kernel-image-2.2.20-mvme147

m68k

2.2.20-3

kernel-image-2.2.20-mvme16x

m68k

2.2.20-3

kernel-patch-2.2.20-powerpc

powerpc

2.2.20-3woody1

For the unstable distribution (sid) this problem will be fixed soon for the architectures that still ship a 2.2.x kernel package.

We recommend that you upgrade your Linux kernel package.

Vulnerability matrix for CAN-2004-0077");

  script_tag(name:"affected", value:"'kernel-image-2.2.20-amiga, kernel-image-2.2.20-atari, kernel-image-2.2.20-bvme6000, kernel-image-2.2.20-i386, kernel-image-2.2.20-mac, kernel-image-2.2.20-mvme16x, kernel-image-2.2.20-mvme147, kernel-image-2.2.20-reiserfs-i386, kernel-patch-2.2.20-powerpc, kernel-source-2.2.20' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
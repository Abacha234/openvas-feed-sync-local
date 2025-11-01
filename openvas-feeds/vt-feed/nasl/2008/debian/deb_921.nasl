# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56013");
  script_cve_id("CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2553", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3275");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-921)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-921");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-921");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-2.4.27-alpha, kernel-image-2.4.27-arm, kernel-image-2.4.27-i386, kernel-image-2.4.27-ia64, kernel-image-2.4.27-m68k, kernel-image-2.4.27-s390, kernel-image-2.4.27-sparc, kernel-patch-2.4.27-arm, kernel-patch-2.4.27-mips, kernel-patch-powerpc-2.4.27, kernel-source-2.4.27' package(s) announced via the DSA-921 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-0756

Alexander Nyberg discovered that the ptrace() system call does not properly verify addresses on the amd64 architecture which can be exploited by a local attacker to crash the kernel.

CVE-2005-0757

A problem in the offset handling in the xattr file system code for ext3 has been discovered that may allow users on 64-bit systems that have access to an ext3 filesystem with extended attributes to cause the kernel to crash.

CVE-2005-1762

A vulnerability has been discovered in the ptrace() system call on the amd64 architecture that allows a local attacker to cause the kernel to crash.

CVE-2005-1767

A vulnerability has been discovered in the stack segment fault handler that could allow a local attacker to cause a stack exception that will lead the kernel to crash under certain circumstances.

CVE-2005-1768

Ilja van Sprundel discovered a race condition in the IA32 (x86) compatibility execve() systemcall for amd64 and IA64 that allows local attackers to cause the kernel to panic and possibly execute arbitrary code.

CVE-2005-2456

Balazs Scheidler discovered that a local attacker could call setsockopt() with an invalid xfrm_user policy message which would cause the kernel to write beyond the boundaries of an array and crash.

CVE-2005-2458

Vladimir Volovich discovered a bug in the zlib routines which are also present in the Linux kernel and allows remote attackers to crash the kernel.

CVE-2005-2459

Another vulnerability has been discovered in the zlib routines which are also present in the Linux kernel and allows remote attackers to crash the kernel.

CVE-2005-2553

A null pointer dereference in ptrace when tracing a 64-bit executable can cause the kernel to crash.

CVE-2005-2801

Andreas Gruenbacher discovered a bug in the ext2 and ext3 file systems. When data areas are to be shared among two inodes not all information were compared for equality, which could expose wrong ACLs for files.

CVE-2005-2872

Chad Walstrom discovered that the ipt_recent kernel module to stop SSH bruteforce attacks could cause the kernel to crash on 64-bit architectures.

CVE-2005-3275

An error in the NAT code allows remote attackers to cause a denial of service (memory corruption) by causing two packets for the same protocol to be NATed at the same time, which leads to memory corruption.

The following matrix explains which kernel version for which architecture fix the problems mentioned above:



Debian 3.1 (sarge)

Source

2.4.27-10sarge1

Alpha architecture

2.4.27-10sarge1

ARM architecture

2.4.27-2sarge1

Intel IA-32 architecture

2.4.27-10sarge1

Intel IA-64 architecture

2.4.27-10sarge1

Motorola 680x0 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-image-2.4.27-alpha, kernel-image-2.4.27-arm, kernel-image-2.4.27-i386, kernel-image-2.4.27-ia64, kernel-image-2.4.27-m68k, kernel-image-2.4.27-s390, kernel-image-2.4.27-sparc, kernel-patch-2.4.27-arm, kernel-patch-2.4.27-mips, kernel-patch-powerpc-2.4.27, kernel-source-2.4.27' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
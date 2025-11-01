# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67406");
  script_cve_id("CVE-2009-4537", "CVE-2010-0727", "CVE-2010-1083", "CVE-2010-1084", "CVE-2010-1086", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1162", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1437", "CVE-2010-1446", "CVE-2010-1451");
  script_tag(name:"creation_date", value:"2010-06-03 20:55:24 +0000 (Thu, 03 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2053");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2053");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4537

Fabian Yamaguchi reported a missing check for Ethernet frames larger than the MTU in the r8169 driver. This may allow users on the local network to crash a system, resulting in a denial of service.

CVE-2010-0727

Sachin Prabhu reported an issue in the GFS2 filesystem. Local users can trigger a BUG() altering the permissions on a locked file, resulting in a denial of service.

CVE-2010-1083

Linus Torvalds reported an issue in the USB subsystem, which may allow local users to obtain portions of sensitive kernel memory.

CVE-2010-1084

Neil Brown reported an issue in the Bluetooth subsystem that may permit remote attackers to overwrite memory through the creation of large numbers of sockets, resulting in a denial of service.

CVE-2010-1086

Ang Way Chuang reported an issue in the DVB subsystem for Digital TV adapters. By creating a specially-encoded MPEG2-TS frame, a remote attacker could cause the receiver to enter an endless loop, resulting in a denial of service.

CVE-2010-1087

Trond Myklebust reported an issue in the NFS filesystem. A local user may cause an oops by sending a fatal signal during a file truncation operation, resulting in a denial of service.

CVE-2010-1088

Al Viro reported an issue where automount symlinks may not be followed when LOOKUP_FOLLOW is not set. This has an unknown security impact.

CVE-2010-1162

Catalin Marinas reported an issue in the tty subsystem that allows local attackers to cause a kernel memory leak, possibly resulting in a denial of service.

CVE-2010-1173

Chris Guo from Nokia China and Jukka Taimisto and Olli Jarva from Codenomicon Ltd reported an issue in the SCTP subsystem that allows a remote attacker to cause a denial of service using a malformed init package.

CVE-2010-1187

Neil Hormon reported an issue in the TIPC subsystem. Local users can cause a denial of service by way of a NULL pointer dereference by sending datagrams through AF_TIPC before entering network mode.

CVE-2010-1437

Toshiyuki Okajima reported a race condition in the keyring subsystem. Local users can cause memory corruption via keyctl commands that access a keyring in the process of being deleted, resulting in a denial of service.

CVE-2010-1446

Wufei reported an issue with kgdb on the PowerPC architecture, allowing local users to write to kernel memory. Note: this issue does not affect binary kernels provided by Debian. The fix is provided for the benefit of users who build their own kernels from Debian source.

CVE-2010-1451

Brad Spengler reported an issue on the SPARC architecture that allows local users to execute non-executable pages.

This update also includes fixes a regression introduced by a previous update. See the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
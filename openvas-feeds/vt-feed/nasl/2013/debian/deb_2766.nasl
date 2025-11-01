# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702766");
  script_cve_id("CVE-2013-2141", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2239", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2888", "CVE-2013-2892");
  script_tag(name:"creation_date", value:"2013-09-26 22:00:00 +0000 (Thu, 26 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2766)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2766");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2766");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2766 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, information leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-2141

Emese Revfy provided a fix for an information leak in the tkill and tgkill system calls. A local user on a 64-bit system may be able to gain access to sensitive memory contents.

CVE-2013-2164

Jonathan Salwan reported an information leak in the CD-ROM driver. A local user on a system with a malfunctioning CD-ROM drive could gain access to sensitive memory.

CVE-2013-2206

Karl Heiss reported an issue in the Linux SCTP implementation. A remote user could cause a denial of service (system crash).

CVE-2013-2232

Dave Jones and Hannes Frederic Sowa resolved an issue in the IPv6 subsystem. Local users could cause a denial of service by using an AF_INET6 socket to connect to an IPv4 destination.

CVE-2013-2234

Mathias Krause reported a memory leak in the implementation of PF_KEYv2 sockets. Local users could gain access to sensitive kernel memory.

CVE-2013-2237

Nicolas Dichtel reported a memory leak in the implementation of PF_KEYv2 sockets. Local users could gain access to sensitive kernel memory.

CVE-2013-2239

Jonathan Salwan discovered multiple memory leaks in the openvz kernel flavor. Local users could gain access to sensitive kernel memory.

CVE-2013-2851

Kees Cook reported an issue in the block subsystem. Local users with uid 0 could gain elevated ring 0 privileges. This is only a security issue for certain specially configured systems.

CVE-2013-2852

Kees Cook reported an issue in the b43 network driver for certain Broadcom wireless devices. Local users with uid 0 could gain elevated ring 0 privileges. This is only a security issue for certain specially configured systems.

CVE-2013-2888

Kees Cook reported an issue in the HID driver subsystem. A local user, with the ability to attach a device, could cause a denial of service (system crash).

CVE-2013-2892

Kees Cook reported an issue in the pantherlord HID device driver. Local users with the ability to attach a device could cause a denial of service or possibly gain elevated privileges.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.6.32-48squeeze4.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:



Debian 6.0 (squeeze)

user-mode-linux

2.6.32-1um-4+48squeeze4

We recommend that you upgrade your linux-2.6 and user-mode-linux packages. Note: Debian carefully tracks all known security issues across every linux kernel package in all releases under active security support. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, updates for lower priority issues ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
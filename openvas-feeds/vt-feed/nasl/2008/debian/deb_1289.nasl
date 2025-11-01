# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58340");
  script_cve_id("CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1289)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1289");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1289");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1289 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1496

Michal Miroslaw reported a DoS vulnerability (crash) in netfilter. A remote attacker can cause a NULL pointer dereference in the nfnetlink_log function.

CVE-2007-1497

Patrick McHardy reported an vulnerability in netfilter that may allow attackers to bypass certain firewall rules. The nfctinfo value of reassembled IPv6 packet fragments were incorrectly initialized to 0 which allowed these packets to become tracked as ESTABLISHED.

CVE-2007-1861

Jaco Kroon reported a bug in which NETLINK_FIB_LOOKUP packages were incorrectly routed back to the kernel resulting in an infinite recursion condition. Local users can exploit this behavior to cause a DoS (crash).

For the stable distribution (etch) these problems have been fixed in version 2.6.18.dfsg.1-12etch2.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch2

user-mode-linux 2.6.18-1um-2etch2

kernel-patch-openvz

028.18.1etch1

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
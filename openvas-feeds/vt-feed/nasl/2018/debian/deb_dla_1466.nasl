# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891466");
  script_cve_id("CVE-2018-13405", "CVE-2018-5390", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2018-08-14 22:00:00 +0000 (Tue, 14 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 18:07:00 +0000 (Wed, 28 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-1466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1466");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1466");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation or denial of service.

CVE-2018-5390

(SegmentSmack)

Juha-Matti Tilli discovered that a remote attacker can trigger the worst case code paths for TCP stream reassembly with low rates of specially crafted packets, leading to remote denial of service.

CVE-2018-5391

(FragmentSmack)

Juha-Matti Tilli discovered a flaw in the way the Linux kernel handled reassembly of fragmented IPv4 and IPv6 packets. A remote attacker can take advantage of this flaw to trigger time and calculation expensive fragment reassembly algorithms by sending specially crafted packets, leading to remote denial of service.

This is mitigated by reducing the default limits on memory usage for incomplete fragmented packets. The same mitigation can be achieved without the need to reboot, by setting the sysctls:

net.ipv4.ipfrag_high_thresh = 262144 net.ipv6.ip6frag_high_thresh = 262144 net.ipv4.ipfrag_low_thresh = 196608 net.ipv6.ip6frag_low_thresh = 196608

The default values may still be increased by local configuration if necessary.

CVE-2018-13405

Jann Horn discovered that the inode_init_owner function in fs/inode.c in the Linux kernel allows local users to create files with an unintended group ownership allowing attackers to escalate privileges by making a plain file executable and SGID.

For Debian 8 Jessie, these problems have been fixed in version 4.9.110-3+deb9u2~deb8u1. This update includes fixes for several regressions in the latest point release.

The earlier version 4.9.110-3+deb9u1~deb8u1 included all the above fixes except for CVE-2018-5391, which may be mitigated as explained above.

We recommend that you upgrade your linux-4.9 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704272");
  script_cve_id("CVE-2018-5391");
  script_tag(name:"creation_date", value:"2018-08-13 22:00:00 +0000 (Mon, 13 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 18:07:00 +0000 (Wed, 28 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-4272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4272");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4272");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-5391 (FragmentSmack) Juha-Matti Tilli discovered a flaw in the way the Linux kernel handled reassembly of fragmented IPv4 and IPv6 packets. A remote attacker can take advantage of this flaw to trigger time and calculation expensive fragment reassembly algorithms by sending specially crafted packets, leading to remote denial of service. This is mitigated by reducing the default limits on memory usage for incomplete fragmented packets. The same mitigation can be achieved without the need to reboot, by setting the sysctls: net.ipv4.ipfrag_low_thresh = 196608 net.ipv6.ip6frag_low_thresh = 196608 net.ipv4.ipfrag_high_thresh = 262144 net.ipv6.ip6frag_high_thresh = 262144 The default values may still be increased by local configuration if necessary.

For the stable distribution (stretch), this problem has been fixed in version 4.9.110-3+deb9u2.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
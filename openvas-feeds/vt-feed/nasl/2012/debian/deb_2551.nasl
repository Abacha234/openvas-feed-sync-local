# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72416");
  script_cve_id("CVE-2012-3955");
  script_tag(name:"creation_date", value:"2012-09-26 15:19:41 +0000 (Wed, 26 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2551");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2551");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'isc-dhcp' package(s) announced via the DSA-2551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Glen Eustace discovered that the ISC DHCP server, a server for automatic IP address assignment, is not properly handling changes in the expiration times of a lease. An attacker may use this flaw to crash the service and cause denial of service conditions, by reducing the expiration time of an active IPv6 lease.

For the stable distribution (squeeze), this problem has been fixed in version 4.1.1-P1-15+squeeze8.

For the testing distribution (wheezy), this problem has been fixed in version 4.2.2.dfsg.1-5+deb70u1.

For the unstable distribution (sid), this problem has been fixed in version 4.2.4-2.

We recommend that you upgrade your isc-dhcp packages.");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
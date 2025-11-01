# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71155");
  script_cve_id("CVE-2011-2748", "CVE-2011-2749");
  script_tag(name:"creation_date", value:"2012-03-12 15:33:55 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2292");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2292");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dhcp3, isc-dhcp' package(s) announced via the DSA-2292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Zych discovered that the ISC DHCP crashes when processing certain packets, leading to a denial of service.

For the oldstable distribution (lenny), this problem has been fixed in version 3.1.1-6+lenny6 of the dhcp3 package.

For the stable distribution (squeeze), this problem has been fixed in version 4.1.1-P1-15+squeeze3 of the isc-dhcp package.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your ISC DHCP packages.");

  script_tag(name:"affected", value:"'dhcp3, isc-dhcp' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
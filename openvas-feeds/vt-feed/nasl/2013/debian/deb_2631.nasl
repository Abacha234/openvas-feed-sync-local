# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702631");
  script_cve_id("CVE-2012-5643", "CVE-2013-0189");
  script_tag(name:"creation_date", value:"2013-02-23 23:00:00 +0000 (Sat, 23 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2631)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2631");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2631");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DSA-2631 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid3, a fully featured Web proxy cache, is prone to a denial of service attack due to memory consumption caused by memory leaks in cachemgr.cgi:

CVE-2012-5643

squid's cachemgr.cgi was vulnerable to excessive resource use. A remote attacker could exploit this flaw to perform a denial of service attack on the server and other hosted services.

CVE-2013-0189

The original patch for CVE-2012-5643 was incomplete. A remote attacker still could exploit this flaw to perform a denial of service attack.

For the stable distribution (squeeze), these problems have been fixed in version 3.1.6-1.2+squeeze3.

For the testing distribution (wheezy), these problems have been fixed in version 3.1.20-2.1.

For the unstable distribution (sid), these problems have been fixed in version 3.1.20-2.1.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
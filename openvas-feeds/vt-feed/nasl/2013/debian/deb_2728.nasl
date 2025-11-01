# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702728");
  script_cve_id("CVE-2013-4854");
  script_tag(name:"creation_date", value:"2013-07-26 22:00:00 +0000 (Fri, 26 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2728)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2728");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2728");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2728 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maxim Shudrak and the HP Zero Day Initiative reported a denial of service vulnerability in BIND, a DNS server. A specially crafted query that includes malformed rdata can cause named daemon to terminate with an assertion failure while rejecting the malformed query.

For the oldstable distribution (squeeze), this problem has been fixed in version 1:9.7.3.dfsg-1~squeeze11.

For the stable distribution (wheezy), this problem has been fixed in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
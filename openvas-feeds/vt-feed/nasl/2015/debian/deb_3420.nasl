# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703420");
  script_cve_id("CVE-2015-8000");
  script_tag(name:"creation_date", value:"2015-12-14 23:00:00 +0000 (Mon, 14 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3420)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3420");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3420");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-3420 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the BIND DNS server does not properly handle the parsing of incoming responses, allowing some records with an incorrect class to be accepted by BIND instead of being rejected as malformed. This can trigger a REQUIRE assertion failure when those records are subsequently cached. A remote attacker can exploit this flaw to cause a denial of service against servers performing recursive queries.

For the oldstable distribution (wheezy), this problem has been fixed in version 1:9.8.4.dfsg.P1-6+nmu2+deb7u8.

For the stable distribution (jessie), this problem has been fixed in version 1:9.9.5.dfsg-9+deb8u4.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69742");
  script_cve_id("CVE-2011-1910");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2244)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2244");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2244");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2244 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BIND, an implementation of the DNS protocol, does not correctly process certain large RRSIG record sets in DNSSEC responses. The resulting assertion failure causes the name server process to crash, making name resolution unavailable. (CVE-2011-1910)

In addition, this update fixes handling of certain signed/unsigned zone combinations when a DLV service is used. Previously, data from certain affected zones could become unavailable from the resolver.

For the oldstable distribution (lenny), this problem has been fixed in version 1:9.6.ESV.R4+dfsg-0+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 1:9.7.3.dfsg-1~squeeze2.

The testing distribution (wheezy) and the unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
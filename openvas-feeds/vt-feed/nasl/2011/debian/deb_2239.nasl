# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69738");
  script_cve_id("CVE-2010-4802", "CVE-2010-4803", "CVE-2011-1841");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2239");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2239");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmojolicious-perl' package(s) announced via the DSA-2239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Mojolicious, a Perl Web Application Framework. The link_to helper was affected by cross-site scripting and implementation errors in the MD5 HMAC and CGI environment handling have been corrected.

The oldstable distribution (lenny) doesn't include libmojolicious-perl.

For the stable distribution (squeeze), this problem has been fixed in version 0.999926-1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 1.12-1.

We recommend that you upgrade your libmojolicious-perl packages.");

  script_tag(name:"affected", value:"'libmojolicious-perl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
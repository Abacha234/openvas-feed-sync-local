# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703098");
  script_cve_id("CVE-2014-9157");
  script_tag(name:"creation_date", value:"2014-12-10 23:00:00 +0000 (Wed, 10 Dec 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3098");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3098");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphviz' package(s) announced via the DSA-3098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joshua Rogers discovered a format string vulnerability in the yyerror function in lib/cgraph/scan.l in Graphviz, a rich set of graph drawing tools. An attacker could use this flaw to cause graphviz to crash or possibly execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 2.26.3-14+deb7u2.

For the upcoming stable distribution (jessie), this problem will be fixed soon in version 2.38.0-7.

For the unstable distribution (sid), this problem has been fixed in version 2.38.0-7.

We recommend that you upgrade your graphviz packages.");

  script_tag(name:"affected", value:"'graphviz' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
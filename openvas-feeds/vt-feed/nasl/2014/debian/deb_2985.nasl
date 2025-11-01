# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702985");
  script_cve_id("CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4258", "CVE-2014-4260");
  script_tag(name:"creation_date", value:"2014-07-21 22:00:00 +0000 (Mon, 21 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2985)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2985");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2985");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-38.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DSA-2985 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to the new upstream version 5.5.38. Please see the MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory for further details:

[link moved to references]

[link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 5.5.38-0+wheezy1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
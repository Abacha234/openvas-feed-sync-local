# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702848");
  script_cve_id("CVE-2013-5891", "CVE-2013-5908", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0437");
  script_tag(name:"creation_date", value:"2014-01-22 23:00:00 +0000 (Wed, 22 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2848)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2848");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2848");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-34.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-35.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DSA-2848 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to the new upstream version 5.5.35. Please see the MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory for further details:

[link moved to references]

[link moved to references]

[link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 5.5.35+dfsg-0+wheezy1.

For the unstable distribution (sid), these problems have been fixed in version 5.5.35+dfsg-1.

We recommend that you upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
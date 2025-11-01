# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703459");
  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616");
  script_tag(name:"creation_date", value:"2016-01-27 23:00:00 +0000 (Wed, 27 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3459)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3459");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3459");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-47.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DSA-3459 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MySQL database server. The vulnerabilities are addressed by upgrading MySQL to the new upstream version 5.5.47. Please see the MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory for further details:

[link moved to references]

[link moved to references]

For the oldstable distribution (wheezy), these problems have been fixed in version 5.5.47-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 5.5.47-0+deb8u1.

We recommend that you upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
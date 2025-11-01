# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844132");
  script_cve_id("CVE-2019-2737", "CVE-2019-2739", "CVE-2019-2740", "CVE-2019-2805");
  script_tag(name:"creation_date", value:"2019-08-14 02:02:10 +0000 (Wed, 14 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 19:39:00 +0000 (Thu, 04 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-4070-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4070-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4070-2");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10141-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/library/mariadb-10141-release-notes/");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-27.html");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-10.1' package(s) announced via the USN-4070-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4070-1 fixed multiple vulnerabilities in MySQL. This update provides the
corresponding fixes for CVE-2019-2737, CVE-2019-2739, CVE-2019-2740,
CVE-2019-2805 in MariaDB 10.1.

Ubuntu 18.04 LTS has been updated to MariaDB 10.1.41.

In addition to security fixes, the updated package contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]

Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 a new upstream MySQL version to fix these issues.

 Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 19.04 have been updated to
 MySQL 5.7.27.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:
 [link moved to references]
 [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.1' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845026");
  script_cve_id("CVE-2021-2372", "CVE-2021-2389");
  script_tag(name:"creation_date", value:"2021-08-17 03:00:37 +0000 (Tue, 17 Aug 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-26 16:30:00 +0000 (Mon, 26 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5022-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5022-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5022-2");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10331-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10512-changelog/");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-35.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-26.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2021.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb-10.3, mariadb-10.5' package(s) announced via the USN-5022-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5022-1 fixed multiple vulnerabilities in MySQL. This update provides the
corresponding fixes for CVE-2021-2372 and CVE-2021-2389 in MariaDB 10.3 and
10.5.

In addition to security fixes, the updated package contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]

Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 new upstream MySQL versions to fix these issues.

 MySQL has been updated to 8.0.26 in Ubuntu 20.04 LTS and Ubuntu 21.04.
 Ubuntu 18.04 LTS has been updated to MySQL 5.7.35.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:

 [link moved to references]
 [link moved to references]
 [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.3, mariadb-10.5' package(s) on Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

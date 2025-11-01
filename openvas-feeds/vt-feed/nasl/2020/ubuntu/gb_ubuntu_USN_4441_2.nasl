# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844530");
  script_tag(name:"creation_date", value:"2020-08-06 03:00:19 +0000 (Thu, 06 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4441-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4441-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4441-2");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-31.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-21.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1889851");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0' package(s) announced via the USN-4441-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4441-1 fixed vulnerabilities in MySQL. The new upstream version
changed compiler options and caused a regression in certain scenarios. This
update fixes the problem.

Original advisory details:

 Multiple security issues were discovered in MySQL and this update includes
 new upstream MySQL versions to fix these issues.

 MySQL has been updated to 8.0.21 in Ubuntu 20.04 LTS. Ubuntu 16.04 LTS and
 Ubuntu 18.04 LTS have been updated to MySQL 5.7.31.

 In addition to security fixes, the updated packages contain bug fixes, new
 features, and possibly incompatible changes.

 Please see the following for more information:

 [link moved to references]

 [link moved to references]

 [link moved to references]");

  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

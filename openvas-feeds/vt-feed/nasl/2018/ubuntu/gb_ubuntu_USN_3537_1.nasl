# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843430");
  script_cve_id("CVE-2018-2562", "CVE-2018-2565", "CVE-2018-2573", "CVE-2018-2576", "CVE-2018-2583", "CVE-2018-2586", "CVE-2018-2590", "CVE-2018-2600", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2645", "CVE-2018-2646", "CVE-2018-2647", "CVE-2018-2665", "CVE-2018-2667", "CVE-2018-2668", "CVE-2018-2696", "CVE-2018-2703");
  script_tag(name:"creation_date", value:"2018-01-23 06:38:42 +0000 (Tue, 23 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-28 01:29:00 +0000 (Wed, 28 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-3537-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3537-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3537-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-21.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5, mysql-5.7' package(s) announced via the USN-3537-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.59 in Ubuntu 14.04 LTS. Ubuntu 16.04 LTS,
and Ubuntu 17.10 have been updated to MySQL 5.7.21.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5, mysql-5.7' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

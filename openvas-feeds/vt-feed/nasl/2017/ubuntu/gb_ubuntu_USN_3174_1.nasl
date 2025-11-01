# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843022");
  script_cve_id("CVE-2016-8318", "CVE-2016-8327", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3251", "CVE-2017-3256", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3273", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3313", "CVE-2017-3317", "CVE-2017-3318", "CVE-2017-3319", "CVE-2017-3320");
  script_tag(name:"creation_date", value:"2017-01-20 04:40:06 +0000 (Fri, 20 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-01 15:17:00 +0000 (Mon, 01 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-3174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3174-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3174-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-54.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-17.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5, mysql-5.7' package(s) announced via the USN-3174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.54 in Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
Ubuntu 16.04 LTS and Ubuntu 16.10 have been updated to MySQL 5.7.17.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5, mysql-5.7' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843146");
  script_cve_id("CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3331", "CVE-2017-3450", "CVE-2017-3453", "CVE-2017-3454", "CVE-2017-3455", "CVE-2017-3456", "CVE-2017-3457", "CVE-2017-3458", "CVE-2017-3459", "CVE-2017-3460", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3465", "CVE-2017-3467", "CVE-2017-3468", "CVE-2017-3599", "CVE-2017-3600");
  script_tag(name:"creation_date", value:"2017-04-28 05:04:48 +0000 (Fri, 28 Apr 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:32:00 +0000 (Tue, 19 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-3269-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3269-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3269-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-55.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-18.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5, mysql-5.7' package(s) announced via the USN-3269-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.55 in Ubuntu 14.04 LTS. Ubuntu 16.04 LTS,
Ubuntu 16.10 and Ubuntu 17.04 have been updated to MySQL 5.7.18.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5, mysql-5.7' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

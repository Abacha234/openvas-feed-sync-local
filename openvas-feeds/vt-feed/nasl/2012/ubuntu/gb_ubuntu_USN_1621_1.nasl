# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841207");
  script_cve_id("CVE-2012-3144", "CVE-2012-3147", "CVE-2012-3149", "CVE-2012-3150", "CVE-2012-3156", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197");
  script_tag(name:"creation_date", value:"2012-11-06 12:18:44 +0000 (Tue, 06 Nov 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1621-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1621-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1621-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-x.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1068158");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.1, mysql-5.5, mysql-dfsg-5.1' package(s) announced via the USN-1621-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.66 in Ubuntu 10.04 LTS and Ubuntu 11.10.
Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.28.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.1, mysql-5.5, mysql-dfsg-5.1' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

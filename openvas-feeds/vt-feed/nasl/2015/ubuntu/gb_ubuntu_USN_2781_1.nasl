# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842503");
  script_cve_id("CVE-2015-4730", "CVE-2015-4766", "CVE-2015-4792", "CVE-2015-4800", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4833", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4862", "CVE-2015-4864", "CVE-2015-4866", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4890", "CVE-2015-4895", "CVE-2015-4904", "CVE-2015-4910", "CVE-2015-4913");
  script_tag(name:"creation_date", value:"2015-10-27 06:08:00 +0000 (Tue, 27 Oct 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2781-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2781-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2781-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-46.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-27.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.5, mysql-5.6' package(s) announced via the USN-2781-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.5.46 in Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
Ubuntu 15.04 and Ubuntu 15.10 have been updated to MySQL 5.6.27.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]
[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.5, mysql-5.6' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

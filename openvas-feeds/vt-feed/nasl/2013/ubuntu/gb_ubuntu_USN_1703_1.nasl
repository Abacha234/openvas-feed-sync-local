# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841291");
  script_cve_id("CVE-2012-0572", "CVE-2012-0574", "CVE-2012-0578", "CVE-2012-1702", "CVE-2012-1705", "CVE-2012-5060", "CVE-2012-5096", "CVE-2012-5611", "CVE-2012-5612", "CVE-2013-0367", "CVE-2013-0368", "CVE-2013-0371", "CVE-2013-0375", "CVE-2013-0383", "CVE-2013-0384", "CVE-2013-0385", "CVE-2013-0386", "CVE-2013-0389");
  script_tag(name:"creation_date", value:"2013-01-24 04:06:50 +0000 (Thu, 24 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:22:00 +0000 (Tue, 19 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-1703-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1703-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1703-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-67.html");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-29.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.1, mysql-5.5, mysql-dfsg-5.1' package(s) announced via the USN-1703-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 5.1.67 in Ubuntu 10.04 LTS and Ubuntu 11.10.
Ubuntu 12.04 LTS and Ubuntu 12.10 have been updated to MySQL 5.5.29.

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

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843880");
  script_cve_id("CVE-2019-2420", "CVE-2019-2434", "CVE-2019-2455", "CVE-2019-2481", "CVE-2019-2482", "CVE-2019-2486", "CVE-2019-2503", "CVE-2019-2507", "CVE-2019-2510", "CVE-2019-2528", "CVE-2019-2529", "CVE-2019-2531", "CVE-2019-2532", "CVE-2019-2534", "CVE-2019-2537");
  script_tag(name:"creation_date", value:"2019-01-24 03:01:35 +0000 (Thu, 24 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3867-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3867-1");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-25.html");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.7' package(s) announced via the USN-3867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
a new upstream MySQL version to fix these issues.

Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 18.10 have been updated to
MySQL 5.7.25.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.7' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

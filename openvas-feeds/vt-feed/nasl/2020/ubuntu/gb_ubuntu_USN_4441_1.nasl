# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844516");
  script_cve_id("CVE-2020-14539", "CVE-2020-14540", "CVE-2020-14547", "CVE-2020-14550", "CVE-2020-14553", "CVE-2020-14559", "CVE-2020-14568", "CVE-2020-14575", "CVE-2020-14576", "CVE-2020-14586", "CVE-2020-14591", "CVE-2020-14597", "CVE-2020-14619", "CVE-2020-14620", "CVE-2020-14623", "CVE-2020-14624", "CVE-2020-14631", "CVE-2020-14632", "CVE-2020-14633", "CVE-2020-14634", "CVE-2020-14641", "CVE-2020-14643", "CVE-2020-14651", "CVE-2020-14654", "CVE-2020-14656", "CVE-2020-14663", "CVE-2020-14678", "CVE-2020-14680", "CVE-2020-14697", "CVE-2020-14702");
  script_tag(name:"creation_date", value:"2020-07-29 03:00:34 +0000 (Wed, 29 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4441-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4441-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-31.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-21.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.7, mysql-8.0' package(s) announced via the USN-4441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.21 in Ubuntu 20.04 LTS. Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS have been updated to MySQL 5.7.31.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]

[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.7, mysql-8.0' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

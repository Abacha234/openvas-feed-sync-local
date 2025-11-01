# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844418");
  script_cve_id("CVE-2020-2759", "CVE-2020-2760", "CVE-2020-2762", "CVE-2020-2763", "CVE-2020-2765", "CVE-2020-2780", "CVE-2020-2804", "CVE-2020-2812", "CVE-2020-2892", "CVE-2020-2893", "CVE-2020-2895", "CVE-2020-2896", "CVE-2020-2897", "CVE-2020-2898", "CVE-2020-2901", "CVE-2020-2903", "CVE-2020-2904", "CVE-2020-2921", "CVE-2020-2922", "CVE-2020-2923", "CVE-2020-2924", "CVE-2020-2925", "CVE-2020-2926", "CVE-2020-2928", "CVE-2020-2930");
  script_tag(name:"creation_date", value:"2020-05-05 03:00:24 +0000 (Tue, 05 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4350-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4350-1");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-30.html");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-20.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-5.7, mysql-8.0' package(s) announced via the USN-4350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.80 in Ubuntu 19.10 and Ubuntu 20.04 LTS.
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS have been updated to MySQL 5.7.30.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:

[link moved to references]

[link moved to references]

[link moved to references]");

  script_tag(name:"affected", value:"'mysql-5.7, mysql-8.0' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

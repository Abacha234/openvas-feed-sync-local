# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840292");
  script_cve_id("CVE-2008-2079", "CVE-2008-3963", "CVE-2008-4097", "CVE-2008-4098");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-671-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-671-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-5.0' package(s) announced via the USN-671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use the
DATA DIRECTORY and INDEX DIRECTORY options to possibly bypass privilege
checks. This update alters table creation behaviour by disallowing the
use of the MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY
options. (CVE-2008-2079, CVE-2008-4097 and CVE-2008-4098)

It was discovered that MySQL did not handle empty bit-string literals
properly. An attacker could exploit this problem and cause the MySQL
server to crash, leading to a denial of service. (CVE-2008-3963)");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

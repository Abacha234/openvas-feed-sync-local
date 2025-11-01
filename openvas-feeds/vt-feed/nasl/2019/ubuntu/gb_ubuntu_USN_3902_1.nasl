# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843925");
  script_cve_id("CVE-2019-9020", "CVE-2019-9021", "CVE-2019-9022", "CVE-2019-9023", "CVE-2019-9024");
  script_tag(name:"creation_date", value:"2019-03-07 03:11:41 +0000 (Thu, 07 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-3902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3902-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3902-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0' package(s) announced via the USN-3902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PHP XML-RPC module incorrectly handled decoding
XML data. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2019-9020, CVE-2019-9024)

It was discovered that the PHP PHAR module incorrectly handled certain
filenames. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service. (CVE-2019-9021)

It was discovered that PHP incorrectly parsed certain DNS responses. A
remote attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. This issue only affected Ubuntu 16.04
LTS. (CVE-2019-9022)

It was discovered that PHP incorrectly handled mbstring regular
expressions. A remote attacker could possibly use this issue to cause PHP
to crash, resulting in a denial of service. (CVE-2019-9023)");

  script_tag(name:"affected", value:"'php5, php7.0' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

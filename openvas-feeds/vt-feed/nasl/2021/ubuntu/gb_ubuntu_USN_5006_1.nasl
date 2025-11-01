# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844997");
  script_cve_id("CVE-2020-7068", "CVE-2020-7071", "CVE-2021-21702", "CVE-2021-21704", "CVE-2021-21705");
  script_tag(name:"creation_date", value:"2021-07-08 03:00:24 +0000 (Thu, 08 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 03:44:00 +0000 (Fri, 08 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5006-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5006-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.2, php7.4' package(s) announced via the USN-5006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain PHAR files. A remote
attacker could possibly use this issue to cause PHP to crash, resulting in
a denial of service, or possibly obtain sensitive information. This issue
only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-7068)

It was discovered that PHP incorrectly handled parsing URLs with passwords.
A remote attacker could possibly use this issue to cause PHP to mis-parse
the URL and produce wrong data. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS, and Ubuntu 20.10. (CVE-2020-7071)

It was discovered that PHP incorrectly handled certain malformed XML data
when being parsed by the SOAP extension. A remote attacker could possibly
use this issue to cause PHP to crash, resulting in a denial of service.
This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
20.10. (CVE-2021-21702)

It was discovered that PHP incorrectly handled the pdo_firebase module. A
remote attacker could possibly use this issue to cause PHP to crash,
resulting in a denial of service. (CVE-2021-21704)

It was discovered that PHP incorrectly handled the FILTER_VALIDATE_URL
check. A remote attacker could possibly use this issue to perform a server-
side request forgery attack. (CVE-2021-21705)");

  script_tag(name:"affected", value:"'php7.2, php7.4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

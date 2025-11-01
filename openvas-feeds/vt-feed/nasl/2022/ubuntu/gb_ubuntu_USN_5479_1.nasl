# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845413");
  script_cve_id("CVE-2022-31625", "CVE-2022-31626");
  script_tag(name:"creation_date", value:"2022-06-16 01:00:30 +0000 (Thu, 16 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-18 13:11:00 +0000 (Thu, 18 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5479-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5479-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.2, php7.4, php8.0, php8.1' package(s) announced via the USN-5479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charles Fol discovered that PHP incorrectly handled initializing certain
arrays when handling the pg_query_params function. A remote attacker could
use this issue to cause PHP to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2022-31625)

Charles Fol discovered that PHP incorrectly handled passwords in mysqlnd. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2022-31626)");

  script_tag(name:"affected", value:"'php7.2, php7.4, php8.0, php8.1' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

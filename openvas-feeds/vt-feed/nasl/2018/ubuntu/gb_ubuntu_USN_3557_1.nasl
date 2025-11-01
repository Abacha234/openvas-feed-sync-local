# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843441");
  script_cve_id("CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-3948", "CVE-2018-1000024", "CVE-2018-1000027");
  script_tag(name:"creation_date", value:"2018-02-06 06:54:09 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 16:15:00 +0000 (Wed, 17 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-3557-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3557-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3557-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-3557-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Fischer discovered that Squid incorrectly handled certain long
strings in headers. A malicious remote server could possibly cause Squid to
crash, resulting in a denial of service. This issue was only addressed in
Ubuntu 16.04 LTS. (CVE-2016-2569)

William Lima discovered that Squid incorrectly handled XML parsing when
processing Edge Side Includes (ESI). A malicious remote server could
possibly cause Squid to crash, resulting in a denial of service. This issue
was only addressed in Ubuntu 16.04 LTS. (CVE-2016-2570)

Alex Rousskov discovered that Squid incorrectly handled response-parsing
failures. A malicious remote server could possibly cause Squid to crash,
resulting in a denial of service. This issue only applied to Ubuntu 16.04
LTS. (CVE-2016-2571)

Santiago Ruano Rincon discovered that Squid incorrectly handled certain
Vary headers. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. This issue was only
addressed in Ubuntu 16.04 LTS. (CVE-2016-3948)

Louis Dion-Marcil discovered that Squid incorrectly handled certain Edge
Side Includes (ESI) responses. A malicious remote server could possibly
cause Squid to crash, resulting in a denial of service. (CVE-2018-1000024)

Louis Dion-Marcil discovered that Squid incorrectly handled certain Edge
Side Includes (ESI) responses. A malicious remote server could possibly
cause Squid to crash, resulting in a denial of service. (CVE-2018-1000027)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

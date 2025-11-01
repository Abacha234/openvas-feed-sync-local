# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843479");
  script_cve_id("CVE-2016-10712", "CVE-2018-5712", "CVE-2018-7584");
  script_tag(name:"creation_date", value:"2018-03-20 07:48:14 +0000 (Tue, 20 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-3600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3600-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3600-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0, php7.1' package(s) announced via the USN-3600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain stream metadata. A
remote attacker could possibly use this issue to set arbitrary metadata.
This issue only affected Ubuntu 14.04 LTS. (CVE-2016-10712)

It was discovered that PHP incorrectly handled the PHAR 404 error page. A
remote attacker could possibly use this issue to conduct cross-site
scripting (XSS) attacks. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 17.10. (CVE-2018-5712)

It was discovered that PHP incorrectly handled parsing certain HTTP
responses. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2018-7584)");

  script_tag(name:"affected", value:"'php5, php7.0, php7.1' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

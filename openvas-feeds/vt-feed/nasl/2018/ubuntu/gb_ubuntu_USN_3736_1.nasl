# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843733");
  script_cve_id("CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166", "CVE-2017-14501", "CVE-2017-14503");
  script_tag(name:"creation_date", value:"2018-10-26 04:12:58 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-28 16:29:00 +0000 (Fri, 28 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3736-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3736-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-3736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled certain archive files.
A remote attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-10209, CVE-2016-10349, CVE-2016-10350)

Agostino Sarubbo discovered that libarchive incorrectly handled certain XAR files.
A remote attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2017-14166)

It was discovered that libarchive incorrectly handled certain files.
A remote attacker could possibly use this issue to get access to sensitive
information. (CVE-2017-14501, CVE-2017-14503)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

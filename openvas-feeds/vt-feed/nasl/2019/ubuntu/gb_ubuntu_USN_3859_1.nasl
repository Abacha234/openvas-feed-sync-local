# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843871");
  script_cve_id("CVE-2017-14502", "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2018-1000880");
  script_tag(name:"creation_date", value:"2019-01-16 03:01:28 +0000 (Wed, 16 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-3859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3859-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3859-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-3859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled certain archive files.
An attacker could possibly use this issue to cause a denial of service.
CVE-2018-1000880 affected only Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2018-1000877, CVE-2018-1000878, CVE-2018-1000880)

It was discovered that libarchive incorrectly handled certain archive files.
An attacker could possibly use this issue to expose sensitive information.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2017-14502)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

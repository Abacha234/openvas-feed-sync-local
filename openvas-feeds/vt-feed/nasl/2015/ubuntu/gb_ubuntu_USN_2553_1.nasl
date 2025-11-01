# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842150");
  script_cve_id("CVE-2014-8127", "CVE-2014-8128", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655");
  script_tag(name:"creation_date", value:"2015-04-01 05:25:08 +0000 (Wed, 01 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-06 13:02:00 +0000 (Fri, 06 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-2553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2553-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2553-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-2553-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"William Robinet discovered that LibTIFF incorrectly handled certain
malformed images. If a user or automated system were tricked into opening a
specially crafted image, a remote attacker could crash the application,
leading to a denial of service, or possibly execute arbitrary code with
user privileges. (CVE-2014-8127, CVE-2014-8128, CVE-2014-8129,
CVE-2014-8130)

Paris Zoumpouloglou discovered that LibTIFF incorrectly handled certain
malformed BMP images. If a user or automated system were tricked into
opening a specially crafted BMP image, a remote attacker could crash the
application, leading to a denial of service. (CVE-2014-9330)

Michal Zalewski discovered that LibTIFF incorrectly handled certain
malformed images. If a user or automated system were tricked into opening a
specially crafted image, a remote attacker could crash the application,
leading to a denial of service, or possibly execute arbitrary code with
user privileges. (CVE-2014-9655)");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

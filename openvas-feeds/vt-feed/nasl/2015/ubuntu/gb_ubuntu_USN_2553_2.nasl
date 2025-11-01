# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842151");
  script_cve_id("CVE-2014-8127", "CVE-2014-8128", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655");
  script_tag(name:"creation_date", value:"2015-04-02 05:12:38 +0000 (Thu, 02 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2553-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2553-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2553-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1439186");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-2553-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2553-1 fixed vulnerabilities in LibTIFF. One of the security fixes
caused a regression when saving certain TIFF files with a Predictor tag.
The problematic patch has been temporarily backed out until a more complete
fix is available.

We apologize for the inconvenience.

Original advisory details:

 William Robinet discovered that LibTIFF incorrectly handled certain
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

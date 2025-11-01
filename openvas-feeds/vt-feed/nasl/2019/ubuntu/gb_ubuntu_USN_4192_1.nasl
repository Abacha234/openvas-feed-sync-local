# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844242");
  script_cve_id("CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12977", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13135", "CVE-2019-13137", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13391", "CVE-2019-13454", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16713");
  script_tag(name:"creation_date", value:"2019-11-15 03:00:52 +0000 (Fri, 15 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-03 12:15:00 +0000 (Fri, 03 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4192-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4192-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4192-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-4192-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick incorrectly handled certain malformed
image files. If a user or automated system using ImageMagick were tricked
into opening a specially crafted image, an attacker could exploit this to
cause a denial of service or possibly execute code with the privileges of
the user invoking the program.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

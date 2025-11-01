# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845143");
  script_cve_id("CVE-2021-20244", "CVE-2021-20246", "CVE-2021-20309", "CVE-2021-20312", "CVE-2021-20313");
  script_tag(name:"creation_date", value:"2021-11-30 02:00:35 +0000 (Tue, 30 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 08:15:00 +0000 (Thu, 03 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-5158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5158-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5158-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-5158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick incorrectly handled certain values
when processing visual effects based image files. By tricking a user into
opening a specially crafted image file, an attacker could crash the
application causing a denial of service. (CVE-2021-20244)

It was discovered that ImageMagick incorrectly handled certain values
when performing resampling operations. By tricking a user into opening
a specially crafted image file, an attacker could crash the application
causing a denial of service. (CVE-2021-20246)

It was discovered that ImageMagick incorrectly handled certain values
when processing visual effects based image files. By tricking a user into
opening a specially crafted image file, an attacker could crash the
application causing a denial of service (CVE-2021-20309)

It was discovered that ImageMagick incorrectly handled certain values
when processing thumbnail image data. By tricking a user into opening
a specially crafted image file, an attacker could crash the application
causing a denial of service. (CVE-2021-20312)

It was discovered that ImageMagick incorrectly handled memory cleanup
when performing certain cryptographic operations. Under certain conditions
sensitive cryptographic information could be disclosed. (CVE-2021-20313)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

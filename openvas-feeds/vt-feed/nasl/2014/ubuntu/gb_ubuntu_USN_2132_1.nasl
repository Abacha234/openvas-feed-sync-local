# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841745");
  script_cve_id("CVE-2012-0260", "CVE-2014-1958", "CVE-2014-2030");
  script_tag(name:"creation_date", value:"2014-03-12 04:11:06 +0000 (Wed, 12 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-11 15:18:00 +0000 (Tue, 11 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2132-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2132-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2132-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-2132-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered that
ImageMagick incorrectly handled certain restart markers in JPEG images. If
a user or automated system using ImageMagick were tricked into opening a
specially crafted JPEG image, an attacker could exploit this to cause
memory consumption, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS. (CVE-2012-0260)

It was discovered that ImageMagick incorrectly handled decoding certain PSD
images. If a user or automated system using ImageMagick were tricked into
opening a specially crafted PSD image, an attacker could exploit this to
cause a denial of service or possibly execute code with the privileges of
the user invoking the program. (CVE-2014-1958, CVE-2014-2030)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

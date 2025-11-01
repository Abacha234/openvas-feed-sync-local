# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843263");
  script_tag(name:"creation_date", value:"2017-08-01 04:53:13 +0000 (Tue, 01 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3363-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3363-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3363-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1707015");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-3363-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3363-1 fixed vulnerabilities in ImageMagick. The update caused a
regression for certain users when processing images. The problematic
patch has been reverted pending further investigation.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that ImageMagick incorrectly handled certain malformed
 image files. If a user or automated system using ImageMagick were tricked
 into opening a specially crafted image, an attacker could exploit this to
 cause a denial of service or possibly execute code with the privileges of
 the user invoking the program.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

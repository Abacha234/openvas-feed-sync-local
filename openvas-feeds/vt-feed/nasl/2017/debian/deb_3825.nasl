# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703825");
  script_cve_id("CVE-2016-3822");
  script_tag(name:"creation_date", value:"2017-03-30 22:00:00 +0000 (Thu, 30 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-05 20:33:00 +0000 (Mon, 05 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-3825)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3825");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3825");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jhead' package(s) announced via the DSA-3825 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that jhead, a tool to manipulate the non-image part of EXIF compliant JPEG files, is prone to an out-of-bounds access vulnerability, which may result in denial of service or, potentially, the execution of arbitrary code if an image with specially crafted EXIF data is processed.

For the stable distribution (jessie), this problem has been fixed in version 1:2.97-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been fixed in version 1:3.00-4.

For the unstable distribution (sid), this problem has been fixed in version 1:3.00-4.

We recommend that you upgrade your jhead packages.");

  script_tag(name:"affected", value:"'jhead' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
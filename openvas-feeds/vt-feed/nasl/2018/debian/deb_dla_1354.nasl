# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891354");
  script_cve_id("CVE-2018-5268", "CVE-2018-5269");
  script_tag(name:"creation_date", value:"2018-04-18 22:00:00 +0000 (Wed, 18 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 18:55:00 +0000 (Tue, 30 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-1354)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1354");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1354");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opencv' package(s) announced via the DLA-1354 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in OpenCV, the Open Computer Vision Library.

CVE-2018-5268

In OpenCV 3.3.1, a heap-based buffer overflow happens in cv::Jpeg2KDecoder::readComponent8u in modules/imgcodecs/src/grfmt_jpeg2000.cpp when parsing a crafted image file.

CVE-2018-5269

In OpenCV 3.3.1, an assertion failure happens in cv::RBaseStream::setPos in modules/imgcodecs/src/bitstrm.cpp because of an incorrect integer cast.

For Debian 7 Wheezy, these problems have been fixed in version 2.3.1-11+deb7u4.

We recommend that you upgrade your opencv packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'opencv' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
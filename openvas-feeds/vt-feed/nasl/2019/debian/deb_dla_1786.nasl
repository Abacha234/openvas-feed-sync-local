# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891786");
  script_cve_id("CVE-2018-15518", "CVE-2018-19869", "CVE-2018-19870", "CVE-2018-19871", "CVE-2018-19873");
  script_tag(name:"creation_date", value:"2019-05-15 02:00:11 +0000 (Wed, 15 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 09:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-1786)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1786");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1786");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qt4-x11' package(s) announced via the DLA-1786 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been addressed in Qt4.

CVE-2018-15518

A double-free or corruption during parsing of a specially crafted illegal XML document.

CVE-2018-19869

A malformed SVG image could cause a segmentation fault in qsvghandler.cpp.

CVE-2018-19870

A malformed GIF image might have caused a NULL pointer dereference in QGifHandler resulting in a segmentation fault.

CVE-2018-19871

There was an uncontrolled resource consumption in QTgaFile.

CVE-2018-19873

QBmpHandler had a buffer overflow via BMP data.

For Debian 8 Jessie, these problems have been fixed in version 4:4.8.6+git64-g5dc8b2b+dfsg-3+deb8u2.

We recommend that you upgrade your qt4-x11 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
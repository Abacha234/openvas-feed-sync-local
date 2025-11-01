# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891501");
  script_cve_id("CVE-2018-16430");
  script_tag(name:"creation_date", value:"2018-09-11 22:00:00 +0000 (Tue, 11 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 12:17:00 +0000 (Thu, 25 Oct 2018)");

  script_name("Debian: Security Advisory (DLA-1501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1501");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libextractor' package(s) announced via the DLA-1501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an out-of-bounds read vulnerability in libextractor, a library to extract meta-data from files of arbitrary type.

For Debian 8 Jessie, this issue has been fixed in libextractor version 1:1.3-2+deb8u3.

We recommend that you upgrade your libextractor packages.");

  script_tag(name:"affected", value:"'libextractor' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
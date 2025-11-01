# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891795");
  script_cve_id("CVE-2019-11473", "CVE-2019-11474", "CVE-2019-11505", "CVE-2019-11506");
  script_tag(name:"creation_date", value:"2019-05-21 02:00:14 +0000 (Tue, 21 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 15:27:00 +0000 (Wed, 01 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-1795)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1795");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1795");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DLA-1795 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in graphicsmagick, the image processing toolkit:

CVE-2019-11473

The WriteMATLABImage function (coders/mat.c) is affected by a heap-based buffer overflow. Remote attackers might leverage this vulnerability to cause denial of service or any other unspecified impact via crafted Matlab matrices.

CVE-2019-11474

The WritePDBImage function (coders/pdb.c) is affected by a heap-based buffer overflow. Remote attackers might leverage this vulnerability to cause denial of service or any other unspecified impact via a crafted Palm Database file.

CVE-2019-11505, CVE-2019-11506 The XWD module (coders/xwd.c) is affected by multiple heap-based buffer overflows and arithmetic exceptions. Remote attackers might leverage these various flaws to cause denial of service or any other unspecified impact via crafted XWD files.

For Debian 8 Jessie, these problems have been fixed in version 1.3.20-3+deb8u7.

We recommend that you upgrade your graphicsmagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
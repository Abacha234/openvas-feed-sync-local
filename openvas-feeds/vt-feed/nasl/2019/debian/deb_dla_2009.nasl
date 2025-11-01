# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892009");
  script_cve_id("CVE-2017-17095", "CVE-2018-12900", "CVE-2018-18661", "CVE-2019-17546", "CVE-2019-6128");
  script_tag(name:"creation_date", value:"2019-11-27 03:00:12 +0000 (Wed, 27 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 18:41:00 +0000 (Wed, 01 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2009");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2009");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-2009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in tiff, a Tag Image File Format library.

CVE-2019-17546

The RGBA interface contains an integer overflow that might lead to heap buffer overflow write.

CVE-2019-6128

A memory leak exists due to missing cleanup code.

CVE-2018-18661

In case of exhausted memory there is a null pointer dereference in tiff2bw.

CVE-2018-12900

Fix for heap-based buffer overflow, that could be used to crash an application or even to execute arbitrary code (with the permission of the user running this application).

CVE-2017-17095

A crafted tiff file could lead to a heap buffer overflow in pal2rgb.

For Debian 8 Jessie, these problems have been fixed in version 4.0.3-12.3+deb8u10.

We recommend that you upgrade your tiff packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
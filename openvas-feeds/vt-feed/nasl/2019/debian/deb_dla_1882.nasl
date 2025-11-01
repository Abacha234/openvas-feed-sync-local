# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891882");
  script_cve_id("CVE-2017-1000159", "CVE-2019-1010006", "CVE-2019-11459");
  script_tag(name:"creation_date", value:"2019-08-14 02:00:12 +0000 (Wed, 14 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1882)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1882");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1882");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'atril' package(s) announced via the DLA-1882 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A few issues were found in Atril, the MATE document viewer.

CVE-2017-1000159

When printing from DVI to PDF, the dvipdfm tool was called without properly sanitizing the filename, which could lead to a command injection attack via the filename.

CVE-2019-11459

The tiff_document_render() and tiff_document_get_thumbnail() did not check the status of TIFFReadRGBAImageOriented(), leading to uninitialized memory access if that function fails.

CVE-2019-1010006

Some buffer overflow checks were not properly done, leading to application crash or possibly arbitrary code execution when opening maliciously crafted files.

For Debian 8 Jessie, these problems have been fixed in version 1.8.1+dfsg1-4+deb8u2.

We recommend that you upgrade your atril packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'atril' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
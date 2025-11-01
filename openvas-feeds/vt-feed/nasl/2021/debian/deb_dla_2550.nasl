# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892550");
  script_cve_id("CVE-2020-27814", "CVE-2020-27823", "CVE-2020-27824", "CVE-2020-27841", "CVE-2020-27845");
  script_tag(name:"creation_date", value:"2021-02-09 04:00:31 +0000 (Tue, 09 Feb 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 17:01:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-2550)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2550");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2550");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openjpeg2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg2' package(s) announced via the DLA-2550 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various overflow errors were identified and fixed.

CVE-2020-27814

A heap-buffer overflow was found in the way openjpeg2 handled certain PNG format files.

CVE-2020-27823

Wrong computation of x1,y1 if -d option is used, resulting in heap buffer overflow.

CVE-2020-27824

Global buffer overflow on irreversible conversion when too many decomposition levels are specified.

CVE-2020-27841

Crafted input to be processed by the openjpeg encoder could cause an out-of-bounds read.

CVE-2020-27844

Crafted input to be processed by the openjpeg encoder could cause an out-of-bounds write.

CVE-2020-27845

Crafted input can cause out-of-bounds-read.

For Debian 9 stretch, these problems have been fixed in version 2.1.2-1.1+deb9u6.

We recommend that you upgrade your openjpeg2 packages.

For the detailed security status of openjpeg2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
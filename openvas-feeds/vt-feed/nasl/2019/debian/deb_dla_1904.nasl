# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891904");
  script_cve_id("CVE-2019-15531");
  script_tag(name:"creation_date", value:"2019-08-31 02:00:06 +0000 (Sat, 31 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-31 17:39:00 +0000 (Thu, 31 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-1904)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1904");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1904");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libextractor' package(s) announced via the DLA-1904 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"jianglin found an issue in libextractor, a library that extracts meta-data from files of arbitrary type.

A crafted file could result in a heap-buffer-overflow vulnerability in function EXTRACTOR_dvi_extract_method in dvi_extractor.c.

For Debian 8 Jessie, this problem has been fixed in version 1:1.3-2+deb8u5.

We recommend that you upgrade your libextractor packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references] DLA-1904-1 (END)");

  script_tag(name:"affected", value:"'libextractor' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
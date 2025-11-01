# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892289");
  script_cve_id("CVE-2018-16647", "CVE-2018-16648", "CVE-2018-18662", "CVE-2019-13290", "CVE-2019-6130");
  script_tag(name:"creation_date", value:"2020-07-26 03:00:10 +0000 (Sun, 26 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-30 00:15:00 +0000 (Sun, 30 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-2289)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2289");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2289");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mupdf");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mupdf' package(s) announced via the DLA-2289 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in mupdf, a lightweight PDF viewer.

The issues could be exploited by crafted PDF files that result in denial of service by heap-based buffer overflows, segmentation faults or out of bound reads.

For Debian 9 stretch, these problems have been fixed in version 1.9a+ds1-4+deb9u5.

We recommend that you upgrade your mupdf packages.

For the detailed security status of mupdf please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mupdf' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
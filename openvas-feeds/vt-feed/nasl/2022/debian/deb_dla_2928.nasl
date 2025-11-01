# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892928");
  script_cve_id("CVE-2021-40985", "CVE-2021-43579", "CVE-2022-0534");
  script_tag(name:"creation_date", value:"2022-02-27 02:00:06 +0000 (Sun, 27 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 15:57:00 +0000 (Fri, 14 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2928)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2928");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2928");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/htmldoc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'htmldoc' package(s) announced via the DLA-2928 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in htmldoc, an HTML processor that generates indexed HTML, PS, and PDF.

CVE-2022-0534

A crafted GIF file could lead to a stack out-of-bounds read, which could result in a crash (segmentation fault).

CVE-2021-43579

Converting an HTML document, which links to a crafted BMP file, could lead to a stack-based buffer overflow, which could result in remote code execution.

CVE-2021-40985

A crafted BMP image could lead to a buffer overflow, which could cause a denial of service.

For Debian 9 stretch, these problems have been fixed in version 1.8.27-8+deb9u2.

We recommend that you upgrade your htmldoc packages.

For the detailed security status of htmldoc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'htmldoc' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
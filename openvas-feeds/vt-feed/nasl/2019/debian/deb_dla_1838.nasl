# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891838");
  script_cve_id("CVE-2018-5686", "CVE-2018-6192", "CVE-2019-6130");
  script_tag(name:"creation_date", value:"2019-06-29 02:00:10 +0000 (Sat, 29 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-26 00:15:00 +0000 (Sun, 26 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-1838)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1838");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1838");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mupdf' package(s) announced via the DLA-1838 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several minor issues have been fixed in mupdf, a lightweight PDF viewer tailored for display of high quality anti-aliased graphics.

CVE-2018-5686

In MuPDF, there was an infinite loop vulnerability and application hang in the pdf_parse_array function (pdf/pdf-parse.c) because EOF not having been considered. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted PDF file.

CVE-2019-6130

MuPDF had a SEGV in the function fz_load_page of the fitz/document.c file, as demonstrated by mutool. This was related to page-number mishandling in cbz/mucbz.c, cbz/muimg.c, and svg/svg-doc.c.

CVE-2018-6192

In MuPDF, the pdf_read_new_xref function in pdf/pdf-xref.c allowed remote attackers to cause a denial of service (segmentation violation and application crash) via a crafted PDF file.

For Debian 8 Jessie, these problems have been fixed in version 1.5-1+deb8u6.

We recommend that you upgrade your mupdf packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mupdf' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
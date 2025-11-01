# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57336");
  script_cve_id("CVE-2006-2440", "CVE-2006-3743", "CVE-2006-3744");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1168");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1168");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-1168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Imagemagick, a collection of image manipulation tools, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-2440

Eero Hakkinen discovered that the display tool allocates insufficient memory for globbing patterns, which might lead to a buffer overflow.

CVE-2006-3743

Tavis Ormandy from the Google Security Team discovered that the Sun bitmap decoder performs insufficient input sanitising, which might lead to buffer overflows and the execution of arbitrary code.

CVE-2006-3744

Tavis Ormandy from the Google Security Team discovered that the XCF image decoder performs insufficient input sanitising, which might lead to buffer overflows and the execution of arbitrary code.

For the stable distribution (sarge) these problems have been fixed in version 6:6.0.6.2-2.7.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
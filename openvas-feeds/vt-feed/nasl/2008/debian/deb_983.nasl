# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56355");
  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2006-0301");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-983)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-983");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-983");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdftohtml' package(s) announced via the DSA-983 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Derek Noonburg has fixed several potential vulnerabilities in xpdf, which are also present in pdftohtml, a utility that translates PDF documents into HTML format.

The old stable distribution (woody) does not contain pdftohtml packages.

For the stable distribution (sarge) these problems have been fixed in version 0.36-11sarge2.

For the unstable distribution (sid) these problems have been fixed in version 0.36-12.

We recommend that you upgrade your pdftohtml package.");

  script_tag(name:"affected", value:"'pdftohtml' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
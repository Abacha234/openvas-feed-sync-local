# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56934");
  script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1095");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1095");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-1095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in the FreeType 2 font engine. The Common vulnerabilities and Exposures project identifies the following problems:

CVE-2006-0747

Several integer underflows have been discovered which could allow remote attackers to cause a denial of service.

CVE-2006-1861

Chris Evans discovered several integer overflows that lead to a denial of service or could possibly even lead to the execution of arbitrary code.

CVE-2006-2493

Several more integer overflows have been discovered which could possibly lead to the execution of arbitrary code.

CVE-2006-2661

A null pointer dereference could cause a denial of service.

For the old stable distribution (woody) these problems have been fixed in version 2.0.9-1woody1.

For the stable distribution (sarge) these problems have been fixed in version 2.1.7-2.5.

For the unstable distribution (sid) these problems will be fixed soon

We recommend that you upgrade your libfreetype packages.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57583");
  script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4571");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1210)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1210");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1210");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-1210 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in Mozilla and derived products such as Mozilla Firefox. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-2788

Fernando Ribeiro discovered that a vulnerability in the getRawDER function allows remote attackers to cause a denial of service (hang) and possibly execute arbitrary code.

CVE-2006-4340

Daniel Bleichenbacher recently described an implementation error in RSA signature verification that cause the application to incorrectly trust SSL certificates.

CVE-2006-4565, CVE-2006-4566 Priit Laes reported that a JavaScript regular expression can trigger a heap-based buffer overflow which allows remote attackers to cause a denial of service and possibly execute arbitrary code.

CVE-2006-4568

A vulnerability has been discovered that allows remote attackers to bypass the security model and inject content into the sub-frame of another site.

CVE-2006-4571

Multiple unspecified vulnerabilities in Firefox, Thunderbird and SeaMonkey allow remote attackers to cause a denial of service, corrupt memory, and possibly execute arbitrary code.

For the stable distribution (sarge) these problems have been fixed in version 1.0.4-2sarge12.

For the unstable distribution (sid) these problems have been fixed in version 1.5.dfsg+1.5.0.7-1 of firefox.

We recommend that you upgrade your Mozilla Firefox packages.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
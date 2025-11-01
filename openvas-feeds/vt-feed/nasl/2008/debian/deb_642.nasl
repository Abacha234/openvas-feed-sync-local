# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53744");
  script_cve_id("CVE-2004-1106");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-642)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-642");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-642");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gallery' package(s) announced via the DSA-642 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in gallery, a web-based photo album written in PHP4. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2004-1106

Jim Paris discovered a cross site scripting vulnerability which allows code to be inserted by using specially formed URLs.

CVE-NOMATCH The upstream developers of gallery have fixed several cases of possible variable injection that could trick gallery to unintended actions, e.g. leaking database passwords.

For the stable distribution (woody) these problems have been fixed in version 1.2.5-8woody3.

For the unstable distribution (sid) these problems have been fixed in version 1.4.4-pl4-1.

We recommend that you upgrade your gallery package.");

  script_tag(name:"affected", value:"'gallery' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
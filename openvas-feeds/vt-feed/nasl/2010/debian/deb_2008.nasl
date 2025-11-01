# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67032");
  script_tag(name:"creation_date", value:"2010-03-16 16:25:39 +0000 (Tue, 16 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2008)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2008");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2008");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2008 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the TYPO3 web content management framework: Cross-site scripting vulnerabilities have been discovered in both the frontend and the backend. Also, user data could be leaked. More details can be found in the Typo3 security advisory.

For the stable distribution (lenny), these problems have been fixed in version 4.2.5-1+lenny3.

For the upcoming stable distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 4.3.2-1.

We recommend that you upgrade your typo3-src package.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
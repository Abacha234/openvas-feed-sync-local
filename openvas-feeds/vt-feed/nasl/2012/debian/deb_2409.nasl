# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71136");
  script_cve_id("CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212");
  script_tag(name:"creation_date", value:"2012-03-12 15:30:53 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2409)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2409");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2409");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'devscripts' package(s) announced via the DSA-2409 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in debdiff, a script used to compare two Debian packages, which is part of the devscripts package. The following Common Vulnerabilities and Exposures project ids have been assigned to identify them:

CVE-2012-0210: Paul Wise discovered that due to insufficient input sanitising when processing .dsc and .changes files, it is possible to execute arbitrary code and disclose system information.

CVE-2012-0211: Raphael Geissert discovered that it is possible to inject or modify arguments of external commands when processing source packages with specially-named tarballs in the top-level directory of the .orig tarball, allowing arbitrary code execution.

CVE-2012-0212: Raphael Geissert discovered that it is possible to inject or modify arguments of external commands when passing as argument to debdiff a specially-named file, allowing arbitrary code execution.

For the stable distribution (squeeze), these problems have been fixed in version 2.10.69+squeeze2.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed in version 2.11.4.

We recommend that you upgrade your devscripts packages.");

  script_tag(name:"affected", value:"'devscripts' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
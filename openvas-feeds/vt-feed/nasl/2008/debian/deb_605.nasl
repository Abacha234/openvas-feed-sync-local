# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53293");
  script_cve_id("CVE-2004-0915");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-605)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-605");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-605");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'viewcvs' package(s) announced via the DSA-605 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Haris Sehic discovered several vulnerabilities in viewcvs, a utility for viewing CVS and Subversion repositories via HTTP. When exporting a repository as a tar archive the hide_cvsroot and forbidden settings were not honoured enough.

When upgrading the package for woody, please make a copy of your /etc/viewcvs/viewcvs.conf file if you have manually edited this file. Upon upgrade the debconf mechanism may alter it in a way so that viewcvs doesn't understand it anymore.

For the stable distribution (woody) these problems have been fixed in version 0.9.2-4woody1.

For the unstable distribution (sid) these problems have been fixed in version 0.9.2+cvs.1.0.dev.2004.07.28-1.2.

We recommend that you upgrade your viewcvs package.");

  script_tag(name:"affected", value:"'viewcvs' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
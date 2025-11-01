# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60784");
  script_cve_id("CVE-2007-4542", "CVE-2007-4629");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1539)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1539");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1539");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mapserver' package(s) announced via the DSA-1539 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Schmidt and Daniel Morissette discovered two vulnerabilities in mapserver, a development environment for spatial and mapping applications. The Common Vulnerabilities and Exposures project identifies the following two problems:

CVE-2007-4542

Lack of input sanitizing and output escaping in the CGI mapserver's template handling and error reporting routines leads to cross-site scripting vulnerabilities.

CVE-2007-4629

Missing bounds checking in mapserver's template handling leads to a stack-based buffer overrun vulnerability, allowing a remote attacker to execute arbitrary code with the privileges of the CGI or httpd user.

For the stable distribution (etch), these problems have been fixed in version 4.10.0-5.1+etch2.

For the unstable distribution (sid), these problems have been fixed in version 4.10.3-1.

We recommend that you upgrade your mapserver (4.10.0-5.1+etch2) package.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
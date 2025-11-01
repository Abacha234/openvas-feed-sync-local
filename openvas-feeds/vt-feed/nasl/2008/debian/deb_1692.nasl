# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63064");
  script_cve_id("CVE-2007-2739");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1692)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1692");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1692");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-xajax' package(s) announced via the DSA-1692 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that php-xajax, a library to develop Ajax applications, did not sufficiently sanitise URLs, which allows attackers to perform cross-site scripting attacks by using malicious URLs.

For the stable distribution (etch) this problem has been fixed in version 0.2.4-2+etch1.

For the testing (lenny) and unstable (sid) distributions this problem has been fixed in version 0.2.5-1.

We recommend that you upgrade your php-xajax package.");

  script_tag(name:"affected", value:"'php-xajax' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
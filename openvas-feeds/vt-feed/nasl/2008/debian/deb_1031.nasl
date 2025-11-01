# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56530");
  script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1031");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1031");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-1031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in libphp-adodb, the 'adodb' database abstraction layer for PHP, which is embedded in cacti, a frontend to rrdtool for monitoring systems and services. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-0146

Andreas Sandblad discovered that improper user input sanitisation results in a potential remote SQL injection vulnerability enabling an attacker to compromise applications, access or modify data, or exploit vulnerabilities in the underlying database implementation. This requires the MySQL root password to be empty. It is fixed by limiting access to the script in question.

CVE-2006-0147

A dynamic code evaluation vulnerability allows remote attackers to execute arbitrary PHP functions via the 'do' parameter.

CVE-2006-0410

Andy Staudacher discovered an SQL injection vulnerability due to insufficient input sanitising that allows remote attackers to execute arbitrary SQL commands.

CVE-2006-0806

GulfTech Security Research discovered multiple cross-site scripting vulnerabilities due to improper user-supplied input sanitisation. Attackers can exploit these vulnerabilities to cause arbitrary scripts to be executed in the browser of an unsuspecting user's machine, or result in the theft of cookie-based authentication credentials.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 0.8.6c-7sarge3.

For the unstable distribution these problems will be fixed soon.

We recommend that you upgrade your cacti package.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
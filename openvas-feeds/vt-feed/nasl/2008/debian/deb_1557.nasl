# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60860");
  script_cve_id("CVE-2008-1149", "CVE-2008-1567", "CVE-2008-1924");
  script_tag(name:"creation_date", value:"2008-04-30 17:28:13 +0000 (Wed, 30 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1557)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1557");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1557");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-1557 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpMyAdmin, an application to administrate MySQL over the WWW. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1924

Attackers with CREATE table permissions were allowed to read arbitrary files readable by the webserver via a crafted HTTP POST request.

CVE-2008-1567

The PHP session data file stored the username and password of a logged in user, which in some setups can be read by a local user.

CVE-2008-1149

Cross site scripting and SQL injection were possible by attackers that had permission to create cookies in the same cookie domain as phpMyAdmin runs in.

For the stable distribution (etch), these problems have been fixed in version 4:2.9.1.1-7.

For the unstable distribution (sid), these problems have been fixed in version 4:2.11.5.2-1.

We recommend that you upgrade your phpmyadmin package.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
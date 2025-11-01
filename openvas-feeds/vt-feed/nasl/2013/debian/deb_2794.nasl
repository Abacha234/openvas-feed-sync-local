# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702794");
  script_cve_id("CVE-2013-4555", "CVE-2013-4556", "CVE-2013-4557");
  script_tag(name:"creation_date", value:"2013-11-09 23:00:00 +0000 (Sat, 09 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2794)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2794");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2794");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DSA-2794 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in SPIP, a website engine for publishing, resulting in cross-site request forgery on logout, cross-site scripting on author page, and PHP injection.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.1.1-3squeeze7.

For the stable distribution (wheezy), these problems have been fixed in version 2.1.17-1+deb7u2.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 2.1.24-1.

For the experimental distribution, these problems have been fixed in version 3.0.12-1.

We recommend that you upgrade your spip packages.");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
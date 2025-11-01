# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63061");
  script_cve_id("CVE-2008-4242");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1689");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1689");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-1689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maksymilian Arciemowicz of securityreason.com reported that ProFTPD is vulnerable to cross-site request forgery (CSRF) attacks and executes arbitrary FTP commands via a long ftp:// URI that leverages an existing session from the FTP client implementation in a web browser.

For the stable distribution (etch) this problem has been fixed in version 1.3.0-19etch2 and in version 1.3.1-15~bpo40+1 for backports.

For the testing (lenny) and unstable (sid) distributions this problem has been fixed in version 1.3.1-15.

We recommend that you upgrade your proftpd-dfsg package.");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
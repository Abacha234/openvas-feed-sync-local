# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61938");
  script_cve_id("CVE-2008-4326");
  script_tag(name:"creation_date", value:"2008-12-03 17:25:22 +0000 (Wed, 03 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1675)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1675");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1675");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-1675 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Masako Oono discovered that phpMyAdmin, a web-based administration interface for MySQL, insufficiently sanitises input allowing a remote attacker to gather sensitive data through cross site scripting, provided that the user uses the Internet Explorer web browser.

This update also fixes a regression introduced in DSA 1641, that broke changing of the language and encoding in the login screen.

For the stable distribution (etch), these problems have been fixed in version 4:2.9.1.1-9.

For the unstable distribution (sid), these problems have been fixed in version 4:2.11.8.1-3.

We recommend that you upgrade your phpmyadmin package.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
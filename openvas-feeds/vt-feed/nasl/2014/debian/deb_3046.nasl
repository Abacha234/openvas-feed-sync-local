# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703046");
  script_cve_id("CVE-2014-7295");
  script_tag(name:"creation_date", value:"2014-10-04 22:00:00 +0000 (Sat, 04 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3046");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3046");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-3046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that MediaWiki, a website engine for collaborative work, allowed to load user-created CSS on pages where user-created JavaScript is not allowed. A wiki user could be tricked into performing actions by manipulating the interface from CSS, or JavaScript code being executed from CSS, on security-wise sensitive pages like Special:Preferences and Special:UserLogin. This update removes the separation of CSS and JavaScript module allowance.

For the stable distribution (wheezy), this problem has been fixed in version 1:1.19.20+dfsg-0+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 1:1.19.20+dfsg-1.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
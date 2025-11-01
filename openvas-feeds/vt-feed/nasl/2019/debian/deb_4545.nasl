# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704545");
  script_cve_id("CVE-2019-16738");
  script_tag(name:"creation_date", value:"2019-10-20 02:00:12 +0000 (Sun, 20 Oct 2019)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-18 19:15:00 +0000 (Fri, 18 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4545)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4545");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4545");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mediawiki");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-4545 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Special:Redirect functionality of MediaWiki, a website engine for collaborative work, could expose suppressed user names, resulting in an information leak.

For the oldstable distribution (stretch), this problem has been fixed in version 1:1.27.7-1~deb9u2.

For the stable distribution (buster), this problem has been fixed in version 1:1.31.4-1~deb10u1.

We recommend that you upgrade your mediawiki packages.

For the detailed security status of mediawiki please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

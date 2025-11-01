# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704592");
  script_cve_id("CVE-2019-19709");
  script_tag(name:"creation_date", value:"2019-12-29 03:00:25 +0000 (Sun, 29 Dec 2019)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-28 18:15:00 +0000 (Sat, 28 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-4592)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4592");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4592");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mediawiki");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DSA-4592 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Title blacklist functionality in MediaWiki, a website engine for collaborative work, could by bypassed.

For the oldstable distribution (stretch), this problem has been fixed in version 1:1.27.7-1~deb9u3.

For the stable distribution (buster), this problem has been fixed in version 1:1.31.6-1~deb10u1.

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

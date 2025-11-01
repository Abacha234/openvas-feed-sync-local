# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892379");
  script_cve_id("CVE-2020-25813", "CVE-2020-25814", "CVE-2020-25827", "CVE-2020-25828");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:12 +0000 (Sat, 26 Sep 2020)");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 03:15:00 +0000 (Mon, 14 Dec 2020)");

  script_name("Debian: Security Advisory (DLA-2379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2379");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2379-3");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mediawiki");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mediawiki' package(s) announced via the DLA-2379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update of mediawiki released as DLA-2379-2 contained a defect in the patch for CVE-2020-25827 which resulted from a possible use of an uninitialized variable. Updated mediawiki packages are now available to correct this issue.

For Debian 9 stretch, this problem has been fixed in version 1:1.27.7-1~deb9u6.

We recommend that you upgrade your mediawiki packages.

For the detailed security status of mediawiki please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

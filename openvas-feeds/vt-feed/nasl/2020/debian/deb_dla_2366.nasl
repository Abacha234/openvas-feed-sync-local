# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892366");
  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-12140", "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12643", "CVE-2017-12674", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12806", "CVE-2017-12875", "CVE-2017-13061", "CVE-2017-13133", "CVE-2017-13658", "CVE-2017-13768", "CVE-2017-14060", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14249", "CVE-2017-14341", "CVE-2017-14400", "CVE-2017-14505", "CVE-2017-14532", "CVE-2017-14624", "CVE-2017-14625", "CVE-2017-14626", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-15015", "CVE-2017-15017", "CVE-2017-15281", "CVE-2017-17682", "CVE-2017-17914", "CVE-2017-18209", "CVE-2017-18211", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-16643", "CVE-2018-16749", "CVE-2018-18025", "CVE-2019-11598", "CVE-2019-13135", "CVE-2019-13308", "CVE-2019-13391", "CVE-2019-15139");
  script_tag(name:"creation_date", value:"2020-09-08 03:00:45 +0000 (Tue, 08 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 00:15:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-2366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2366");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2366");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/imagemagick");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-2366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Debian Bug : 870020 870019 876105 869727 886281 873059 870504 870530 870107 872609 875338 875339 875341 873871 873131 875352 878506 875503 875502 876105 876099 878546 878545 877354 877355 878524 878547 878548 878555 878554 878548 878555 878554 878579 885942 886584 928206 941670 931447 932079

Several security vulnerabilities were found in Imagemagick. Various memory handling problems and cases of missing or incomplete input sanitizing may result in denial of service, memory or CPU exhaustion, information disclosure or potentially the execution of arbitrary code when a malformed image file is processed.

For Debian 9 stretch, these problems have been fixed in version 8:6.9.7.4+dfsg-11+deb9u10.

We recommend that you upgrade your imagemagick packages.

For the detailed security status of imagemagick please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891131");
  script_cve_id("CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12875", "CVE-2017-13758", "CVE-2017-13768", "CVE-2017-13769", "CVE-2017-14060", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14224", "CVE-2017-14249", "CVE-2017-14341", "CVE-2017-14400", "CVE-2017-14505", "CVE-2017-14607", "CVE-2017-14682", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-14989", "CVE-2017-15016", "CVE-2017-15017");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 16:07:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-1131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1131");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1131");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DLA-1131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updates fixes numerous vulnerabilities in imagemagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service, memory disclosure, or the execution of arbitrary code if malformed XCF, VIFF, BMP, thumbnail, CUT, PSD, TXT, XBM, PCX, MPC, WPG, TIFF, SVG, font, EMF, PNG, or other types of files are processed.

For Debian 7 Wheezy, these problems have been fixed in version 8:6.7.7.10-5+deb7u17.

We recommend that you upgrade your imagemagick packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
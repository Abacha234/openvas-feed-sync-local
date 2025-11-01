# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703799");
  script_cve_id("CVE-2016-10062", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10146", "CVE-2016-8707", "CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5510", "CVE-2017-5511");
  script_tag(name:"creation_date", value:"2017-02-28 23:00:00 +0000 (Tue, 28 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 16:08:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-3799)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3799");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3799");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3799 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several vulnerabilities in imagemagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service or the execution of arbitrary code if malformed TIFF, WPG, IPL, MPC or PSB files are processed.

For the stable distribution (jessie), these problems have been fixed in version 8:6.8.9.9-5+deb8u7.

For the testing distribution (stretch), these problems have been fixed in version 8:6.9.7.4+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 8:6.9.7.4+dfsg-1.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
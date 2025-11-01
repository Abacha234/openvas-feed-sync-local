# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703726");
  script_cve_id("CVE-2016-10059", "CVE-2016-10061", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10066", "CVE-2016-10067", "CVE-2016-10068", "CVE-2016-10069", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-7799", "CVE-2016-7906", "CVE-2016-8677", "CVE-2016-8862", "CVE-2016-9556", "CVE-2016-9559");
  script_tag(name:"creation_date", value:"2016-11-25 23:00:00 +0000 (Fri, 25 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-26 15:32:00 +0000 (Mon, 26 Apr 2021)");

  script_name("Debian: Security Advisory (DSA-3726)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3726");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3726");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3726 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in ImageMagick, a popular set of programs and libraries for image manipulation. These issues include several problems in memory handling that can result in a denial of service attack or in execution of arbitrary code by an attacker with control on the image input.

For the stable distribution (jessie), these problems have been fixed in version 8:6.8.9.9-5+deb8u6.

For the unstable distribution (sid), these problems have been fixed in version 8:6.9.6.5+dfsg-1.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
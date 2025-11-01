# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703808");
  script_cve_id("CVE-2016-10252", "CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500");
  script_tag(name:"creation_date", value:"2017-03-12 23:00:00 +0000 (Sun, 12 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3808)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3808");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3808");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3808 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several vulnerabilities in imagemagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service or the execution of arbitrary code if malformed TGA, Sun or PSD files are processed.

This update also fixes visual artefacts when running -sharpen on CMYK images (no security impact, but piggybacked on top of the security update with approval of the Debian stable release managers since it's a regression in jessie compared to wheezy).

For the stable distribution (jessie), these problems have been fixed in version 8:6.8.9.9-5+deb8u8.

For the upcoming stable distribution (stretch), these problems have been fixed in version 8:6.9.7.4+dfsg-2.

For the unstable distribution (sid), these problems have been fixed in version 8:6.9.7.4+dfsg-2.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
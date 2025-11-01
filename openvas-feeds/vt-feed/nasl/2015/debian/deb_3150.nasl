# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703150");
  script_cve_id("CVE-2014-9626", "CVE-2014-9627", "CVE-2014-9628", "CVE-2014-9629", "CVE-2014-9630");
  script_tag(name:"creation_date", value:"2015-02-01 23:00:00 +0000 (Sun, 01 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 16:17:00 +0000 (Wed, 29 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3150");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3150");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-3150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabian Yamaguchi discovered multiple vulnerabilities in VLC, a multimedia player and streamer:

CVE-2014-9626

The MP4 demuxer, when parsing string boxes, did not properly check the length of the box, leading to a possible integer underflow when using this length value in a call to memcpy(). This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution via crafted MP4 files.

CVE-2014-9627

The MP4 demuxer, when parsing string boxes, did not properly check that the conversion of the box length from 64bit integer to 32bit integer on 32bit platforms did not cause a truncation, leading to a possible buffer overflow. This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution via crafted MP4 files.

CVE-2014-9628

The MP4 demuxer, when parsing string boxes, did not properly check the length of the box, leading to a possible buffer overflow. This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution via crafted MP4 files.

CVE-2014-9629

The Dirac and Schroedinger encoders did not properly check for an integer overflow on 32bit platforms, leading to a possible buffer overflow. This could allow remote attackers to cause a denial of service (crash) or arbitrary code execution.

For the stable distribution (wheezy), these problems have been fixed in version 2.0.3-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have been fixed in version 2.2.0~rc2-2.

For the unstable distribution (sid), these problems have been fixed in version 2.2.0~rc2-2.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
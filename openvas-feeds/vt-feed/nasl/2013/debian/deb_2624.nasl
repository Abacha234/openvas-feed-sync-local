# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702624");
  script_cve_id("CVE-2012-0858", "CVE-2012-2777", "CVE-2012-2783", "CVE-2012-2784", "CVE-2012-2788", "CVE-2012-2801", "CVE-2012-2803");
  script_tag(name:"creation_date", value:"2013-02-15 23:00:00 +0000 (Fri, 15 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2624)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2624");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2624");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DSA-2624 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in FFmpeg, a multimedia player, server and encoder. Multiple input validations in the decoders/demuxers for Shorten, Chinese AVS video, VP5, VP6, AVI, AVS and MPEG-1/2 files could lead to the execution of arbitrary code.

Most of these issues were discovered by Mateusz Jurczyk and Gynvael Coldwind.

For the stable distribution (squeeze), these problems have been fixed in version 4:0.5.10-1.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 6:0.8.5-1 of the source package libav.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
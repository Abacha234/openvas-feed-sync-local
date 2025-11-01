# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66953");
  script_cve_id("CVE-2009-4631", "CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4637", "CVE-2009-4638", "CVE-2009-4640");
  script_tag(name:"creation_date", value:"2010-02-25 21:02:04 +0000 (Thu, 25 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2000)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2000");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2000");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg-debian' package(s) announced via the DSA-2000 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ffmpeg, a multimedia player, server and encoder, which also provides a range of multimedia libraries used in applications like MPlayer:

Various programming errors in container and codec implementations may lead to denial of service or the execution of arbitrary code if the user is tricked into opening a malformed media file or stream.

The implementations of the following affected codecs and container formats have been updated:

the Vorbis audio codec

the Ogg container implementation

the FF Video 1 codec

the MPEG audio codec

the H264 video codec

the MOV container implementation

the Oggedc container implementation

For the stable distribution (lenny), these problems have been fixed in version 0.svn20080206-18+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 4:0.5+svn20090706-5.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"affected", value:"'ffmpeg-debian' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
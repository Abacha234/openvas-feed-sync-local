# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60789");
  script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2008-0073", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0984", "CVE-2008-1489");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1543)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1543");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1543");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-1543 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Luigi Auriemma, Alin Rad Pop, Remi Denis-Courmont, Quovodis, Guido Landi, Felipe Manzano, Anibal Sacco and others discovered multiple vulnerabilities in vlc, an application for playback and streaming of audio and video. In the worst case, these weaknesses permit a remote, unauthenticated attacker to execute arbitrary code with the privileges of the user running vlc.

The Common Vulnerabilities and Exposures project identifies the following eight problems:

CVE-2007-6681

A buffer overflow vulnerability in subtitle handling allows an attacker to execute arbitrary code through the opening of a maliciously crafted MicroDVD, SSA or Vplayer file.

CVE-2007-6682

A format string vulnerability in the HTTP-based remote control facility of the vlc application allows a remote, unauthenticated attacker to execute arbitrary code.

CVE-2007-6683

Insecure argument validation allows a remote attacker to overwrite arbitrary files writable by the user running vlc, if a maliciously crafted M3U playlist or MP3 audio file is opened.

CVE-2008-0295, CVE-2008-0296 Heap buffer overflows in RTSP stream and session description protocol (SDP) handling allow an attacker to execute arbitrary code if a maliciously crafted RTSP stream is played.

CVE-2008-0073

Insufficient integer bounds checking in SDP handling allows the execution of arbitrary code through a maliciously crafted SDP stream ID parameter in an RTSP stream.

CVE-2008-0984

Insufficient integrity checking in the MP4 demuxer allows a remote attacker to overwrite arbitrary memory and execute arbitrary code if a maliciously crafted MP4 file is opened.

CVE-2008-1489

An integer overflow vulnerability in MP4 handling allows a remote attacker to cause a heap buffer overflow, inducing a crash and possibly the execution of arbitrary code if a maliciously crafted MP4 file is opened.

For the stable distribution (etch), these problems have been fixed in version 0.8.6-svn20061012.debian-5.1+etch2.

For the unstable distribution (sid), these problems have been fixed in version 0.8.6.e-2.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
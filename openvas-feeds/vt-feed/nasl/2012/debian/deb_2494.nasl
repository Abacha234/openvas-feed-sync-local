# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71472");
  script_cve_id("CVE-2011-3951", "CVE-2011-3952", "CVE-2012-0851", "CVE-2012-0852");
  script_tag(name:"creation_date", value:"2012-08-10 07:05:54 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2494");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2494");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DSA-2494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg, Debian's version of the Libav media codec suite, contains vulnerabilities in the DPCM codecs (CVE-2011-3951), H.264 (CVE-2012-0851), ADPCM (CVE-2012-0852), and the KMVC decoder (CVE-2011-3952).

In addition, this update contains bug fixes from the Libav 0.5.9 upstream release.

For the stable distribution (squeeze), these problems have been fixed in version 4:0.5.9-1.

For the unstable distribution (sid), these problems have been fixed in version 6:0.8.3-1.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
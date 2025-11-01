# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703288");
  script_cve_id("CVE-2015-3395", "CVE-2015-3417");
  script_tag(name:"creation_date", value:"2015-06-12 22:00:00 +0000 (Fri, 12 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3288)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3288");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3288");
  script_xref(name:"URL", value:"https://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v11.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DSA-3288 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library. A full list of the changes is available at [link moved to references]

For the stable distribution (jessie), these problems have been fixed in version 6:11.4-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 6:11.4-1.

For the unstable distribution (sid), these problems have been fixed in version 6:11.4-1.

We recommend that you upgrade your libav packages.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
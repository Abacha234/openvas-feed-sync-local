# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703003");
  script_cve_id("CVE-2011-3934", "CVE-2011-3935", "CVE-2011-3946", "CVE-2013-0848", "CVE-2013-0851", "CVE-2013-0852", "CVE-2013-0860", "CVE-2013-0868", "CVE-2013-3672", "CVE-2013-3674", "CVE-2014-2263");
  script_tag(name:"creation_date", value:"2014-08-09 22:00:00 +0000 (Sat, 09 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3003");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3003");
  script_xref(name:"URL", value:"http://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v0.8.15");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DSA-3003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library. A full list of the changes is available at [link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 6:0.8.15-1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your libav packages.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
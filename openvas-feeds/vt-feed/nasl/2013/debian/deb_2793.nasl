# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702793");
  script_cve_id("CVE-2013-0844", "CVE-2013-0850", "CVE-2013-0853", "CVE-2013-0854", "CVE-2013-0857", "CVE-2013-0858", "CVE-2013-0866");
  script_tag(name:"creation_date", value:"2013-11-08 23:00:00 +0000 (Fri, 08 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2793)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2793");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2793");
  script_xref(name:"URL", value:"http://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v0.8.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DSA-2793 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library. The CVE IDs mentioned above are just a small portion of the security issues fixed in this update. A full list of the changes is available at [link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 0.8.9-1.

For the unstable distribution (sid), these problems have been fixed in version 9.10-1.

We recommend that you upgrade your libav packages.");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
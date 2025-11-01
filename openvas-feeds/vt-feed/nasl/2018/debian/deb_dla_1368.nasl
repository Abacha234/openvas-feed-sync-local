# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891368");
  script_cve_id("CVE-2017-11333", "CVE-2017-14632", "CVE-2017-14633", "CVE-2018-5146");
  script_tag(name:"creation_date", value:"2018-05-01 22:00:00 +0000 (Tue, 01 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 20:26:00 +0000 (Mon, 07 Dec 2020)");

  script_name("Debian: Security Advisory (DLA-1368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1368");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1368");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvorbis' package(s) announced via the DLA-1368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Serious vulnerabilities were found in the libvorbis library, commonly used to encode and decode audio in OGG containers.

CVE-2017-14633

In Xiph.Org libvorbis 1.3.5, an out-of-bounds array read vulnerability exists in the function mapping0_forward() in mapping0.c, which may lead to DoS when operating on a crafted audio file with vorbis_analysis().

CVE-2017-14632

Xiph.Org libvorbis 1.3.5 allows Remote Code Execution upon freeing uninitialized memory in the function vorbis_analysis_headerout() in info.c when vi->channels<=0, a similar issue to Mozilla bug 550184.

CVE-2017-11333

The vorbis_analysis_wrote function in lib/block.c in Xiph.Org libvorbis 1.3.5 allows remote attackers to cause a denial of service (OOM) via a crafted wav file.

CVE-2018-5146

out-of-bounds memory write in the codeboook parsing code of the Libvorbis multimedia library could result in the execution of arbitrary code.

For Debian 7 Wheezy, these problems have been fixed in version 1.3.2-1.3+deb7u1.

We recommend that you upgrade your libvorbis packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libvorbis' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
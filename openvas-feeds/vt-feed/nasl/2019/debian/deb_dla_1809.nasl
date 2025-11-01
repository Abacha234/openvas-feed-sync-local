# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891809");
  script_cve_id("CVE-2018-15822", "CVE-2019-11338");
  script_tag(name:"creation_date", value:"2019-06-01 09:22:32 +0000 (Sat, 01 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 17:50:00 +0000 (Fri, 07 Oct 2022)");

  script_name("Debian: Security Advisory (DLA-1809)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1809");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1809");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DLA-1809 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two more security issues have been corrected in multiple demuxers and decoders of the libav multimedia library.

CVE-2018-15822

The flv_write_packet function in libavformat/flvenc.c in libav did not check for an empty audio packet, leading to an assertion failure.

CVE-2019-11338

libavcodec/hevcdec.c in libav mishandled detection of duplicate first slices, which allowed remote attackers to cause a denial of service (NULL pointer dereference and out-of-array access) or possibly have unspecified other impact via crafted HEVC data.

For Debian 8 Jessie, these problems have been fixed in version 6:11.12-1~deb8u7.

We recommend that you upgrade your libav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
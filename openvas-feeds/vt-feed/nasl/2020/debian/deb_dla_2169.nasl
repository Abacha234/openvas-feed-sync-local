# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892169");
  script_cve_id("CVE-2017-9831", "CVE-2017-9832");
  script_tag(name:"creation_date", value:"2020-04-06 03:00:08 +0000 (Mon, 06 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-05 17:15:00 +0000 (Sun, 05 Apr 2020)");

  script_name("Debian: Security Advisory (DLA-2169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2169");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2169");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmtp' package(s) announced via the DLA-2169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libmtp is a library for communicating with MTP aware devices. The Media Transfer Protocol (commonly referred to as MTP) is a devised set of custom extensions to support the transfer of music files on USB digital audio players and movie files on USB portable media players.

CVE-2017-9831

An integer overflow vulnerability in the ptp_unpack_EOS_CustomFuncEx function of the ptp-pack.c file allows attackers to cause a denial of service (out-of-bounds memory access) or maybe remote code execution by inserting a mobile device into a personal computer through a USB cable.

CVE-2017-9832

An integer overflow vulnerability in ptp-pack.c (ptp_unpack_OPL function) allows attackers to cause a denial of service (out-of-bounds memory access) or maybe remote code execution by inserting a mobile device into a personal computer through a USB cable.

For Debian 8 Jessie, these problems have been fixed in version 1.1.8-1+deb8u1.

We recommend that you upgrade your libmtp packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libmtp' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
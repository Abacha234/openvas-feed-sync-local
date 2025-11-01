# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891392");
  script_cve_id("CVE-2018-1093", "CVE-2018-10940", "CVE-2018-1130", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2018-06-03 22:00:00 +0000 (Sun, 03 Jun 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1392)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1392");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1392");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1392 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service.

CVE-2018-1093

Wen Xu reported that a crafted ext4 filesystem image could trigger an out-of-bounds read in the ext4_valid_block_bitmap() function. A local user able to mount arbitrary filesystems could use this for denial of service.

CVE-2018-1130

The syzbot software found that the DCCP implementation of sendmsg() does not check the socket state, potentially leading to a null pointer dereference. A local user could use this to cause a denial of service (crash).

CVE-2018-8897

Nick Peterson of Everdox Tech LLC discovered that #DB exceptions that are deferred by MOV SS or POP SS are not properly handled, allowing an unprivileged user to crash the kernel and cause a denial of service.

CVE-2018-10940

Dan Carpenter reported that the cdrom driver does not correctly validate the parameter to the CDROM_MEDIA_CHANGED ioctl. A user with access to a cdrom device could use this to cause a denial of service (crash).

For Debian 7 Wheezy, these problems have been fixed in version 3.2.102-1. This version also includes bug fixes from upstream version 3.2.102, including a fix for a regression in the SCTP implementation in version 3.2.101.

We recommend that you upgrade your linux packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
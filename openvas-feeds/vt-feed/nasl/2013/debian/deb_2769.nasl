# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702769");
  script_cve_id("CVE-2013-5691", "CVE-2013-5710");
  script_tag(name:"creation_date", value:"2013-10-07 22:00:00 +0000 (Mon, 07 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2769)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2769");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2769");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kfreebsd-9' package(s) announced via the DSA-2769 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FreeBSD kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-5691

Loganaden Velvindron and Gleb Smirnoff discovered that the SIOCSIFADDR, SIOCSIFBRDADDR, SIOCSIFDSTADDR and SIOCSIFNETMASK ioctl requests do not perform input validation or verify the caller's credentials. Unprivileged user with the ability to run arbitrary code can cause any network interface in the system to perform the link layer actions associated with the above ioctl requests or trigger a kernel panic by passing a specially crafted address structure which causes a network interface driver to dereference an invalid pointer.

CVE-2013-5710

Konstantin Belousov discovered that the nullfs(5) implementation of the VOP_LINK(9) VFS operation does not check whether the source and target of the link are both in the same nullfs instance. It is therefore possible to create a hardlink from a location in one nullfs instance to a file in another, as long as the underlying (source) filesystem is the same. If multiple nullfs views into the same filesystem are mounted in different locations, a user may gain write access to files which are nominally on a read-only filesystem.

For the stable distribution (wheezy), these problems have been fixed in version 9.0-10+deb70.4.

We recommend that you upgrade your kfreebsd-9 packages.");

  script_tag(name:"affected", value:"'kfreebsd-9' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
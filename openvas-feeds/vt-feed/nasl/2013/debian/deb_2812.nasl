# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702812");
  script_cve_id("CVE-2013-4408", "CVE-2013-4475");
  script_tag(name:"creation_date", value:"2013-12-08 23:00:00 +0000 (Sun, 08 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2812)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2812");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2812");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-2812 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues were found in Samba, a SMB/CIFS file, print, and login server:

CVE-2013-4408

It was discovered that multiple buffer overflows in the processing of DCE-RPC packets may lead to the execution of arbitrary code.

CVE-2013-4475

Hemanth Thummala discovered that ACLs were not checked when opening files with alternate data streams. This issue is only exploitable if the VFS modules vfs_streams_depot and/or vfs_streams_xattr are used.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.5.6~dfsg-3squeeze11.

For the stable distribution (wheezy), these problems have been fixed in version 3.6.6-6+deb7u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
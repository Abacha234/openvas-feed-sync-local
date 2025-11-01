# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703166");
  script_cve_id("CVE-2015-0247", "CVE-2015-1572");
  script_tag(name:"creation_date", value:"2015-02-21 23:00:00 +0000 (Sat, 21 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3166)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3166");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3166");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'e2fsprogs' package(s) announced via the DSA-3166 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jose Duart of the Google Security Team discovered a buffer overflow in e2fsprogs, a set of utilities for the ext2, ext3, and ext4 file systems. This issue can possibly lead to arbitrary code execution if a malicious device is plugged in, the system is configured to automatically mount it, and the mounting process chooses to run fsck on the device's malicious filesystem.

CVE-2015-0247

Buffer overflow in the ext2/ext3/ext4 file system open/close routines.

CVE-2015-1572

Incomplete fix for CVE-2015-0247.

For the stable distribution (wheezy), these problems have been fixed in version 1.42.5-1.1+deb7u1.

For the upcoming stable (jessie) and unstable (sid) distributions, these problems will be fixed soon.

We recommend that you upgrade your e2fsprogs packages.");

  script_tag(name:"affected", value:"'e2fsprogs' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
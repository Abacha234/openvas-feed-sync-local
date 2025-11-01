# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67981");
  script_cve_id("CVE-2009-4895", "CVE-2010-2226", "CVE-2010-2240", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2798", "CVE-2010-2803", "CVE-2010-2959", "CVE-2010-3015");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 16:03:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2094");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2094");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2094 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4895

Kyle Bader reported an issue in the tty subsystem that allows local users to create a denial of service (NULL pointer dereference).

CVE-2010-2226

Dan Rosenberg reported an issue in the xfs filesystem that allows local users to copy and read a file owned by another user, for which they only have write permissions, due to a lack of permission checking in the XFS_SWAPEXT ioctl.

CVE-2010-2240

Rafal Wojtczuk reported an issue that allows users to obtain escalated privileges. Users must already have sufficient privileges to execute or connect clients to an Xorg server.

CVE-2010-2248

Suresh Jayaraman discovered an issue in the CIFS filesystem. A malicious file server can set an incorrect 'CountHigh' value, resulting in a denial of service (BUG_ON() assertion).

CVE-2010-2521

Neil Brown reported an issue in the NFSv4 server code. A malicious client could trigger a denial of service (Oops) on a server due to a bug in the read_buf() routine.

CVE-2010-2798

Bob Peterson reported an issue in the GFS2 file system. A file system user could cause a denial of service (Oops) via certain rename operations.

CVE-2010-2803

Kees Cook reported an issue in the DRM (Direct Rendering Manager) subsystem. Local users with sufficient privileges (local X users or members of the 'video' group on a default Debian install) could acquire access to sensitive kernel memory.

CVE-2010-2959

Ben Hawkes discovered an issue in the AF_CAN socket family. An integer overflow condition may allow local users to obtain elevated privileges.

CVE-2010-3015

Toshiyuki Okajima reported an issue in the ext4 filesystem. Local users could trigger a denial of service (BUG assertion) by generating a specific set of filesystem operations.

This update also includes fixes a regression introduced by a previous update. See the referenced Debian bug page for details.

For the stable distribution (lenny), this problem has been fixed in version 2.6.26-24lenny1.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 5.0 (lenny)

user-mode-linux 2.6.26-1um-2+24lenny1

Updates for arm and mips will be released as they become available.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
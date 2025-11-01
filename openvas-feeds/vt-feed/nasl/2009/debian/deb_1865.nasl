# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64748");
  script_cve_id("CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-2692");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1865)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1865");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1865");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1865 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1385

Neil Horman discovered a missing fix from the e1000 network driver. A remote user may cause a denial of service by way of a kernel panic triggered by specially crafted frame sizes.

CVE-2009-1389

Michael Tokarev discovered an issue in the r8169 network driver. Remote users on the same LAN may cause a denial of service by way of a kernel panic triggered by receiving a large size frame.

CVE-2009-1630

Frank Filz discovered that local users may be able to execute files without execute permission when accessed via an nfs4 mount.

CVE-2009-1633

Jeff Layton and Suresh Jayaraman fixed several buffer overflows in the CIFS filesystem which allow remote servers to cause memory corruption.

CVE-2009-2692

Tavis Ormandy and Julien Tinnes discovered an issue with how the sendpage function is initialized in the proto_ops structure. Local users can exploit this vulnerability to gain elevated privileges.

For the oldstable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-24etch3.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch.24etch3

user-mode-linux 2.6.18-1um-2etch.24etch3

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.

Note: Debian carefully tracks all known security issues across every linux kernel package in all releases under active security support. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, updates for lower priority issues will normally not be released for all kernels at the same time. Rather, they will be released in a staggered or 'leap-frog' fashion.");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
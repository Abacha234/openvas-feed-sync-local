# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64555");
  script_cve_id("CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1895", "CVE-2009-1914", "CVE-2009-1961", "CVE-2009-2406", "CVE-2009-2407");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1844)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1844");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1844");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6.24' package(s) announced via the DSA-1844 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1385

Neil Horman discovered a missing fix from the e1000 network driver. A remote user may cause a denial of service by way of a kernel panic triggered by specially crafted frame sizes.

CVE-2009-1389

Michael Tokarev discovered an issue in the r8169 network driver. Remote users on the same LAN may cause a denial of service by way of a kernel panic triggered by receiving a large size frame.

CVE-2009-1630

Frank Filz discovered that local users may be able to execute files without execute permission when accessed via an nfs4 mount.

CVE-2009-1633

Jeff Layton and Suresh Jayaraman fixed several buffer overflows in the CIFS filesystem which allow remote servers to cause memory corruption.

CVE-2009-1895

Julien Tinnes and Tavis Ormandy reported an issue in the Linux personality code. Local users can take advantage of a setuid binary that can either be made to dereference a NULL pointer or drop privileges and return control to the user. This allows a user to bypass mmap_min_addr restrictions which can be exploited to execute arbitrary code.

CVE-2009-1914

Mikulas Patocka discovered an issue in sparc64 kernels that allows local users to cause a denial of service (crash) by reading the /proc/iomem file.

CVE-2009-1961

Miklos Szeredi reported an issue in the ocfs2 filesystem. Local users can create a denial of service (filesystem deadlock) using a particular sequence of splice system calls.

CVE-2009-2406

CVE-2009-2407

Ramon de Carvalho Valle discovered two issues with the eCryptfs layered filesystem using the fsfuzzer utility. A local user with permissions to perform an eCryptfs mount may modify the contents of a eCryptfs file, overflowing the stack and potentially gaining elevated privileges.

For the stable distribution (etch), these problems have been fixed in version 2.6.24-6~etchnhalf.8etch2.

We recommend that you upgrade your linux-2.6.24 packages.

Note: Debian 'etch' includes linux kernel packages based upon both the 2.6.18 and 2.6.24 linux releases. All known security issues are carefully tracked against both packages and both packages will receive security updates until security support for Debian 'etch' concludes. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, lower severity 2.6.18 and 2.6.24 updates will typically release in a staggered or 'leap-frog' fashion.");

  script_tag(name:"affected", value:"'linux-2.6.24' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
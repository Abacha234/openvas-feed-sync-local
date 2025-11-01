# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68091");
  script_cve_id("CVE-2010-2492", "CVE-2010-2954", "CVE-2010-3078", "CVE-2010-3080", "CVE-2010-3081");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 14:43:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2110)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2110");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2110");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2110 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2492

Andre Osterhues reported an issue in the eCryptfs subsystem. A buffer overflow condition may allow local users to cause a denial of service or gain elevated privileges.

CVE-2010-2954

Tavis Ormandy reported an issue in the irda subsystem which may allow local users to cause a denial of service via a NULL pointer dereference.

CVE-2010-3078

Dan Rosenberg discovered an issue in the XFS file system that allows local users to read potentially sensitive kernel memory.

CVE-2010-3080

Tavis Ormandy reported an issue in the ALSA sequencer OSS emulation layer. Local users with sufficient privileges to open /dev/sequencer (by default on Debian, this is members of the 'audio' group) can cause a denial of service via a NULL pointer dereference.

CVE-2010-3081

Ben Hawkes discovered an issue in the 32-bit compatibility code for 64-bit systems. Local users can gain elevated privileges due to insufficient checks in compat_alloc_user_space allocations.

For the stable distribution (lenny), this problem has been fixed in version 2.6.26-25lenny1.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 5.0 (lenny)

user-mode-linux 2.6.26-1um-2+25lenny1");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
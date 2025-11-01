# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64755");
  script_cve_id("CVE-2009-2698", "CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1872)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1872");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1872");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1872 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to denial of service, privilege escalation or a leak of sensitive memory. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2698

Herbert Xu discovered an issue in the way UDP tracks corking status that could allow local users to cause a denial of service (system crash). Tavis Ormandy and Julien Tinnes discovered that this issue could also be used by local users to gain elevated privileges.

CVE-2009-2846

Michael Buesch noticed a typing issue in the eisa-eeprom driver for the hppa architecture. Local users could exploit this issue to gain access to restricted memory.

CVE-2009-2847

Ulrich Drepper noticed an issue in the do_sigalstack routine on 64-bit systems. This issue allows local users to gain access to potentially sensitive memory on the kernel stack.

CVE-2009-2848

Eric Dumazet discovered an issue in the execve path, where the clear_child_tid variable was not being properly cleared. Local users could exploit this issue to cause a denial of service (memory corruption).

CVE-2009-2849

Neil Brown discovered an issue in the sysfs interface to md devices. When md arrays are not active, local users can exploit this vulnerability to cause a denial of service (oops).

For the oldstable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-24etch4.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.

Note: Debian carefully tracks all known security issues across every linux kernel package in all releases under active security support. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, updates for lower priority issues will normally not be released for all kernels at the same time. Rather, they will be released in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch.24etch4

user-mode-linux 2.6.18-1um-2etch.24etch4");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
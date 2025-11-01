# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66207");
  script_cve_id("CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3638");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1927)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1927");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1927");
  script_xref(name:"URL", value:"https://wiki.debian.org/mmap_min_addr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1927 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Notice: Debian 5.0.4, the next point release of Debian 'lenny', will include a new default value for the mmap_min_addr tunable. This change will add an additional safeguard against a class of security vulnerabilities known as 'NULL pointer dereference' vulnerabilities, but it will need to be overridden when using certain applications. Additional information about this change, including instructions for making this change locally in advance of 5.0.4 (recommended), can be found at: [link moved to references].

Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, sensitive memory leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3228

Eric Dumazet reported an instance of uninitialized kernel memory in the network packet scheduler. Local users may be able to exploit this issue to read the contents of sensitive kernel memory.

CVE-2009-3238

Linus Torvalds provided a change to the get_random_int() function to increase its randomness.

CVE-2009-3547

Earl Chew discovered a NULL pointer dereference issue in the pipe_rdwr_open function which can be used by local users to gain elevated privileges.

CVE-2009-3612

Jiri Pirko discovered a typo in the initialization of a structure in the netlink subsystem that may allow local users to gain access to sensitive kernel memory.

CVE-2009-3620

Ben Hutchings discovered an issue in the DRM manager for ATI Rage 128 graphics adapters. Local users may be able to exploit this vulnerability to cause a denial of service (NULL pointer dereference).

CVE-2009-3621

Tomoki Sekiyama discovered a deadlock condition in the UNIX domain socket implementation. Local users can exploit this vulnerability to cause a denial of service (system hang).

CVE-2009-3638

David Wagner reported an overflow in the KVM subsystem on i386 systems. This issue is exploitable by local users with access to the /dev/kvm device file.

For the stable distribution (lenny), this problem has been fixed in version 2.6.26-19lenny2.

For the oldstable distribution (etch), these problems, where applicable, will be fixed in updates to linux-2.6 and linux-2.6.24.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

Note: Debian carefully tracks all known security issues across every linux kernel package in all releases under active security support. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, updates for lower priority issues will normally not be released for all kernels at the same time. Rather, they will be released in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 5.0 (lenny)

user-mode-linux 2.6.26-1um-2+19lenny2");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
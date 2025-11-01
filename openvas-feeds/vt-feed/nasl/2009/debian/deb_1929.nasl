# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66209");
  script_cve_id("CVE-2009-1883", "CVE-2009-2909", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3621");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1929)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1929");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1929");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1929 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, sensitive memory leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-1883

Solar Designer discovered a missing capability check in the z90crypt driver or s390 systems. This vulnerability may allow a local user to gain elevated privileges.

CVE-2009-2909

Arjan van de Ven discovered an issue in the AX.25 protocol implementation. A specially crafted call to setsockopt() can result in a denial of service (kernel oops).

CVE-2009-3001

Jiri Slaby fixed a sensitive memory leak issue in the ANSI/IEEE 802.2 LLC implementation. This is not exploitable in the Debian lenny kernel as root privileges are required to exploit this issue.

CVE-2009-3002

Eric Dumazet fixed several sensitive memory leaks in the IrDA, X.25 PLP (Rose), NET/ROM, Acorn Econet/AUN, and Controller Area Network (CAN) implementations. Local users can exploit these issues to gain access to kernel memory.

CVE-2009-3228

Eric Dumazet reported an instance of uninitialized kernel memory in the network packet scheduler. Local users may be able to exploit this issue to read the contents of sensitive kernel memory.

CVE-2009-3238

Linus Torvalds provided a change to the get_random_int() function to increase its randomness.

CVE-2009-3286

Eric Paris discovered an issue with the NFSv4 server implementation. When an O_EXCL create fails, files may be left with corrupted permissions, possibly granting unintentional privileges to other local users.

CVE-2009-3547

Earl Chew discovered a NULL pointer dereference issue in the pipe_rdwr_open function which can be used by local users to gain elevated privileges.

CVE-2009-3612

Jiri Pirko discovered a typo in the initialization of a structure in the netlink subsystem that may allow local users to gain access to sensitive kernel memory.

CVE-2009-3621

Tomoki Sekiyama discovered a deadlock condition in the UNIX domain socket implementation. Local users can exploit this vulnerability to cause a denial of service (system hang).

For the oldstable distribution (etch), this problem has been fixed in version 2.6.18.dfsg.1-26etch1.

We recommend that you upgrade your linux-2.6, fai-kernels, and user-mode-linux packages.

Note: Debian 'etch' includes linux kernel packages based upon both the 2.6.18 and 2.6.24 linux releases. All known security issues are carefully tracked against both packages and both packages will receive security updates until security support for Debian 'etch' concludes. However, given the high frequency at which low-severity security issues are discovered in the kernel and the resource requirements of doing an update, lower severity 2.6.18 and 2.6.24 updates will typically release in a staggered or 'leap-frog' fashion.

The following matrix lists additional source packages that were rebuilt ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
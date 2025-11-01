# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66208");
  script_cve_id("CVE-2009-2846", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3228", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621");
  script_tag(name:"creation_date", value:"2009-11-11 14:56:44 +0000 (Wed, 11 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-1928)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1928");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1928");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6.24' package(s) announced via the DSA-1928 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, sensitive memory leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2846

Michael Buesch noticed a typing issue in the eisa-eeprom driver for the hppa architecture. Local users could exploit this issue to gain access to restricted memory.

CVE-2009-2847

Ulrich Drepper noticed an issue in the do_sigalstack routine on 64-bit systems. This issue allows local users to gain access to potentially sensitive memory on the kernel stack.

CVE-2009-2848

Eric Dumazet discovered an issue in the execve path, where the clear_child_tid variable was not being properly cleared. Local users could exploit this issue to cause a denial of service (memory corruption).

CVE-2009-2849

Neil Brown discovered an issue in the sysfs interface to md devices. When md arrays are not active, local users can exploit this vulnerability to cause a denial of service (oops).

CVE-2009-2903

Mark Smith discovered a memory leak in the appletalk implementation. When the appletalk and ipddp modules are loaded, but no ipddp'N' device is found, remote attackers can cause a denial of service by consuming large amounts of system memory.

CVE-2009-2908

Loic Minier discovered an issue in the eCryptfs filesystem. A local user can cause a denial of service (kernel oops) by causing a dentry value to go negative.

CVE-2009-2909

Arjan van de Ven discovered an issue in the AX.25 protocol implementation. A specially crafted call to setsockopt() can result in a denial of service (kernel oops).

CVE-2009-2910

Jan Beulich discovered the existence of a sensitive kernel memory leak. Systems running the 'amd64' kernel do not properly sanitize registers for 32-bit processes.

CVE-2009-3001

Jiri Slaby fixed a sensitive memory leak issue in the ANSI/IEEE 802.2 LLC implementation. This is not exploitable in the Debian lenny kernel as root privileges are required to exploit this issue.

CVE-2009-3002

Eric Dumazet fixed several sensitive memory leaks in the IrDA, X.25 PLP (Rose), NET/ROM, Acorn Econet/AUN, and Controller Area Network (CAN) implementations. Local users can exploit these issues to gain access to kernel memory.

CVE-2009-3228

Eric Dumazet reported an instance of uninitialized kernel memory in the network packet scheduler. Local users may be able to exploit this issue to read the contents of sensitive kernel memory. CVE-2009-3238 Linus Torvalds provided a change to the get_random_int() function to increase its randomness. CVE-2009-3286 Eric Paris discovered an issue with the NFSv4 server implementation. When an O_EXCL create fails, files may be left with corrupted permissions, possibly granting unintentional privileges to other local users. CVE-2009-3547 Earl Chew discovered a NULL pointer dereference issue in the pipe_rdwr_open function which ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6.24' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
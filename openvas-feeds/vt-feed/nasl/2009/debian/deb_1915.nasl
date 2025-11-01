# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66098");
  script_cve_id("CVE-2009-2695", "CVE-2009-2903", "CVE-2009-2908", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3001", "CVE-2009-3002", "CVE-2009-3286", "CVE-2009-3290", "CVE-2009-3613");
  script_tag(name:"creation_date", value:"2009-10-27 00:37:56 +0000 (Tue, 27 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1915)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1915");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1915");
  script_xref(name:"URL", value:"https://wiki.debian.org/mmap_min_addr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1915 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Notice: Debian 5.0.4, the next point release of Debian 'lenny', will include a new default value for the mmap_min_addr tunable. This change will add an additional safeguard against a class of security vulnerabilities known as 'NULL pointer dereference' vulnerabilities, but it will need to be overridden when using certain applications. Additional information about this change, including instructions for making this change locally in advance of 5.0.4 (recommended), can be found at: [link moved to references].

Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, sensitive memory leak or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2695

Eric Paris provided several fixes to increase the protection provided by the mmap_min_addr tunable against NULL pointer dereference vulnerabilities.

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

CVE-2009-3286

Eric Paris discovered an issue with the NFSv4 server implementation. When an O_EXCL create fails, files may be left with corrupted permissions, possibly granting unintentional privileges to other local users.

CVE-2009-3290

Jan Kiszka noticed that the kvm_emulate_hypercall function in KVM does not prevent access to MMU hypercalls from ring 0, which allows local guest OS users to cause a denial of service (guest kernel crash) and read or write guest kernel memory.

CVE-2009-3613

Alistair Strachan reported an issue in the r8169 driver. Remote users can cause a denial of service (IOMMU space exhaustion and system crash) by transmitting a large amount of jumbo frames.

For the oldstable distribution (etch), these problems, where ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58528");
  script_cve_id("CVE-2006-5753", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3848", "CVE-2007-3851");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1356");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1356");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1353

Ilja van Sprundel discovered that kernel memory could be leaked via the Bluetooth setsockopt call due to an uninitialized stack buffer. This could be used by local attackers to read the contents of sensitive kernel memory.

CVE-2007-2172

Thomas Graf reported a typo in the DECnet protocol handler that could be used by a local attacker to overrun an array via crafted packets, potentially resulting in a Denial of Service (system crash). A similar issue exists in the IPV4 protocol handler and will be fixed in a subsequent update.

CVE-2007-2453

A couple of issues with random number generation were discovered. Slightly less random numbers resulted from hashing a subset of the available entropy. Zero-entropy systems were seeded with the same inputs at boot time, resulting in repeatable series of random numbers.

CVE-2007-2525

Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused by releasing a socket before PPPIOCGCHAN is called upon it. This could be used by a local user to DoS a system by consuming all available memory.

CVE-2007-2876

Vilmos Nebehaj discovered a NULL pointer dereference condition in the netfilter subsystem. This allows remote systems which communicate using the SCTP protocol to crash a system by creating a connection with an unknown chunk type.

CVE-2007-3513

Oliver Neukum reported an issue in the usblcd driver which, by not limiting the size of write buffers, permits local users with write access to trigger a DoS by consuming all available memory.

CVE-2007-3642

Zhongling Wen reported an issue in nf_conntrack_h323 where the lack of range checking may lead to NULL pointer dereferences. Remote attackers could exploit this to create a DoS condition (system crash).

CVE-2007-3848

Wojciech Purczynski discovered that pdeath_signal was not being reset properly under certain conditions which may allow local users to gain privileges by sending arbitrary signals to suid binaries.

CVE-2007-3851

Dave Airlie reported that Intel 965 and above chipsets have relocated their batch buffer security bits. Local X server users may exploit this to write user data to arbitrary physical memory addresses.

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch1.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch4

user-mode-linux 2.6.18-1um-2etch3

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
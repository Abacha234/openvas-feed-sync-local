# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703170");
  script_cve_id("CVE-2013-7421", "CVE-2014-7822", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9585", "CVE-2014-9644", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1593");
  script_tag(name:"creation_date", value:"2015-02-22 23:00:00 +0000 (Sun, 22 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:42:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3170");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3170");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, information leaks or privilege escalation.

CVE-2013-7421 / CVE-2014-9644 It was discovered that the Crypto API allowed unprivileged users to load arbitrary kernel modules. A local user can use this flaw to exploit vulnerabilities in modules that would not normally be loaded.

CVE-2014-7822

Akira Fujita found that the splice() system call did not validate the given file offset and length. A local unprivileged user can use this flaw to cause filesystem corruption on ext4 filesystems, or possibly other effects.

CVE-2014-8160

Florian Westphal discovered that a netfilter (iptables/ip6tables) rule accepting packets to a specific SCTP, DCCP, GRE or UDPlite port/endpoint could result in incorrect connection tracking state. If only the generic connection tracking module (nf_conntrack) was loaded, and not the protocol-specific connection tracking module, this would allow access to any port/endpoint of the specified protocol.

CVE-2014-8559

It was found that kernel functions that iterate over a directory tree can dead-lock or live-lock in case some of the directory entries were recently deleted or dropped from the cache. A local unprivileged user can use this flaw for denial of service.

CVE-2014-9585

Andy Lutomirski discovered that address randomisation for the vDSO in 64-bit processes is extremely biased. A local unprivileged user could potentially use this flaw to bypass the ASLR protection mechanism.

CVE-2014-9683

Dmitry Chernenkov discovered that eCryptfs writes past the end of the allocated buffer during encrypted filename decoding, resulting in local denial of service.

CVE-2015-0239

It was found that KVM did not correctly emulate the x86 SYSENTER instruction. An unprivileged user within a guest system that has not enabled SYSENTER, for example because the emulated CPU vendor is AMD, could potentially use this flaw to cause a denial of service or privilege escalation in that guest.

CVE-2015-1420

It was discovered that the open_by_handle_at() system call reads the handle size from user memory a second time after validating it. A local user with the CAP_DAC_READ_SEARCH capability could use this flaw for privilege escalation.

CVE-2015-1421

It was found that the SCTP implementation could free an authentication state while it was still in use, resulting in heap corruption. This could allow remote users to cause a denial of service or privilege escalation.

CVE-2015-1593

It was found that address randomisation for the initial stack in 64-bit processes was limited to 20 rather than 22 bits of entropy. A local unprivileged user could potentially use this flaw to bypass the ASLR protection mechanism.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.65-1+deb7u2. Additionally this update fixes regressions introduced in versions ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
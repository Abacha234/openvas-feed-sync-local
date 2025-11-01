# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703237");
  script_cve_id("CVE-2014-8159", "CVE-2014-9715", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339");
  script_tag(name:"creation_date", value:"2015-04-25 22:00:00 +0000 (Sat, 25 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3237");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3237");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2014-8159

It was found that the Linux kernel's InfiniBand/RDMA subsystem did not properly sanitize input parameters while registering memory regions from user space via the (u)verbs API. A local user with access to a /dev/infiniband/uverbsX device could use this flaw to crash the system or, potentially, escalate their privileges on the system.

CVE-2014-9715

It was found that the netfilter connection tracking subsystem used too small a type as an offset within each connection's data structure, following a bug fix in Linux 3.2.33 and 3.6. In some configurations, this would lead to memory corruption and crashes (even without malicious traffic). This could potentially also result in violation of the netfilter policy or remote code execution.

This can be mitigated by disabling connection tracking accounting: sysctl net.netfilter.nf_conntrack_acct=0

CVE-2015-2041

Sasha Levin discovered that the LLC subsystem exposed some variables as sysctls with the wrong type. On a 64-bit kernel, this possibly allows privilege escalation from a process with CAP_NET_ADMIN capability, it also results in a trivial information leak.

CVE-2015-2042

Sasha Levin discovered that the RDS subsystem exposed some variables as sysctls with the wrong type. On a 64-bit kernel, this results in a trivial information leak.

CVE-2015-2150

Jan Beulich discovered that Xen guests are currently permitted to modify all of the (writable) bits in the PCI command register of devices passed through to them. This in particular allows them to disable memory and I/O decoding on the device unless the device is an SR-IOV virtual function, which can result in denial of service to the host.

CVE-2015-2830

Andrew Lutomirski discovered that when a 64-bit task on an amd64 kernel makes a fork(2) or clone(2) system call using int $0x80, the 32-bit compatibility flag is set (correctly) but is not cleared on return. As a result, both seccomp and audit will misinterpret the following system call by the task(s), possibly leading to a violation of security policy.

CVE-2015-2922

Modio AB discovered that the IPv6 subsystem would process a router advertisement that specifies no route but only a hop limit, which would then be applied to the interface that received it. This can result in loss of IPv6 connectivity beyond the local network.

This may be mitigated by disabling processing of IPv6 router advertisements if they are not needed: sysctl net.ipv6.conf.default.accept_ra=0 sysctl net.ipv6.conf.<interface>.accept_ra=0

CVE-2015-3331

Stephan Mueller discovered that the optimised implementation of RFC4106 GCM for x86 processors that support AESNI miscalculated buffer addresses in some cases. If an IPsec tunnel is configured to use this mode (also known as AES-GCM-ESP) this can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
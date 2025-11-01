# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704667");
  script_cve_id("CVE-2020-10942", "CVE-2020-11565", "CVE-2020-11884", "CVE-2020-2732", "CVE-2020-8428");
  script_tag(name:"creation_date", value:"2020-04-30 03:00:30 +0000 (Thu, 30 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 22:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4667)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4667");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4667");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4667 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, or information leak.

CVE-2020-2732

Paulo Bonzini discovered that the KVM implementation for Intel processors did not properly handle instruction emulation for L2 guests when nested virtualization is enabled. This could allow an L2 guest to cause privilege escalation, denial of service, or information leaks in the L1 guest.

CVE-2020-8428

Al Viro discovered a use-after-free vulnerability in the VFS layer. This allowed local users to cause a denial-of-service (crash) or obtain sensitive information from kernel memory.

CVE-2020-10942

It was discovered that the vhost_net driver did not properly validate the type of sockets set as back-ends. A local user permitted to access /dev/vhost-net could use this to cause a stack corruption via crafted system calls, resulting in denial of service (crash) or possibly privilege escalation.

CVE-2020-11565

Entropy Moe reported that the shared memory filesystem (tmpfs) did not correctly handle an mpol mount option specifying an empty node list, leading to a stack-based out-of-bounds write. If user namespaces are enabled, a local user could use this to cause a denial of service (crash) or possibly for privilege escalation.

CVE-2020-11884

Al Viro reported a race condition in memory management code for IBM Z (s390x architecture), that can result in the kernel executing code from the user address space. A local user could use this for privilege escalation.

For the stable distribution (buster), these problems have been fixed in version 4.19.98-1+deb10u1.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
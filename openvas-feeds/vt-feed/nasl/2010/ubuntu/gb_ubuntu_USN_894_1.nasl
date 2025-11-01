# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840383");
  script_cve_id("CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4031", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4308", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0006", "CVE-2010-0007", "CVE-2010-0291");
  script_tag(name:"creation_date", value:"2010-02-08 10:34:22 +0000 (Mon, 08 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-894-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-894-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-894-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2, linux-fsl-imx51, linux-mvl-dove, linux-source-2.6.15' package(s) announced via the USN-894-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Amerigo Wang and Eric Sesterhenn discovered that the HFS and ext4
filesystems did not correctly check certain disk structures. If a user
were tricked into mounting a specially crafted filesystem, a remote
attacker could crash the system or gain root privileges. (CVE-2009-4020,
CVE-2009-4308)

It was discovered that FUSE did not correctly check certain requests.
A local attacker with access to FUSE mounts could exploit this to
crash the system or possibly gain root privileges. Ubuntu 9.10 was not
affected. (CVE-2009-4021)

It was discovered that KVM did not correctly decode certain guest
instructions. A local attacker in a guest could exploit this to
trigger high scheduling latency in the host, leading to a denial of
service. Ubuntu 6.06 was not affected. (CVE-2009-4031)

It was discovered that the OHCI fireware driver did not correctly
handle certain ioctls. A local attacker could exploit this to crash
the system, or possibly gain root privileges. Ubuntu 6.06 was not
affected. (CVE-2009-4138)

Tavis Ormandy discovered that the kernel did not correctly handle
O_ASYNC on locked files. A local attacker could exploit this to gain
root privileges. Only Ubuntu 9.04 and 9.10 were affected. (CVE-2009-4141)

Neil Horman and Eugene Teo discovered that the e1000 and e1000e
network drivers did not correctly check the size of Ethernet frames.
An attacker on the local network could send specially crafted traffic
to bypass packet filters, crash the system, or possibly gain root
privileges. (CVE-2009-4536, CVE-2009-4538)

It was discovered that 'print-fatal-signals' reporting could show
arbitrary kernel memory contents. A local attacker could exploit
this, leading to a loss of privacy. By default this is disabled in
Ubuntu and did not affect Ubuntu 6.06. (CVE-2010-0003)

Olli Jarva and Tuomo Untinen discovered that IPv6 did not correctly
handle jumbo frames. A remote attacker could exploit this to crash the
system, leading to a denial of service. Only Ubuntu 9.04 and 9.10 were
affected. (CVE-2010-0006)

Florian Westphal discovered that bridging netfilter rules could be
modified by unprivileged users. A local attacker could disrupt network
traffic, leading to a denial of service. (CVE-2010-0007)

Al Viro discovered that certain mremap operations could leak kernel
memory. A local attacker could exploit this to consume all available
memory, leading to a denial of service. (CVE-2010-0291)");

  script_tag(name:"affected", value:"'linux, linux-ec2, linux-fsl-imx51, linux-mvl-dove, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

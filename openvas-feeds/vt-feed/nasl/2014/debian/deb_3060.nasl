# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703060");
  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-7207");
  script_tag(name:"creation_date", value:"2014-10-30 23:00:00 +0000 (Thu, 30 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 13:51:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3060");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3060");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service:

CVE-2014-3610

Lars Bull of Google and Nadav Amit reported a flaw in how KVM handles noncanonical writes to certain MSR registers. A privileged guest user can exploit this flaw to cause a denial of service (kernel panic) on the host.

CVE-2014-3611

Lars Bull of Google reported a race condition in the PIT emulation code in KVM. A local guest user with access to PIT i/o ports could exploit this flaw to cause a denial of service (crash) on the host.

CVE-2014-3645 / CVE-2014-3646 The Advanced Threat Research team at Intel Security discovered that the KVM subsystem did not handle the VM exits gracefully for the invept (Invalidate Translations Derived from EPT) and invvpid (Invalidate Translations Based on VPID) instructions. On hosts with an Intel processor and invept/invppid VM exit support, an unprivileged guest user could use these instructions to crash the guest.

CVE-2014-3647

Nadav Amit reported that KVM mishandles noncanonical addresses when emulating instructions that change rip, potentially causing a failed VM-entry. A guest user with access to I/O or the MMIO can use this flaw to cause a denial of service (system crash) of the guest.

CVE-2014-3673

Liu Wei of Red Hat discovered a flaw in net/core/skbuff.c leading to a kernel panic when receiving malformed ASCONF chunks. A remote attacker could use this flaw to crash the system.

CVE-2014-3687

A flaw in the sctp stack was discovered leading to a kernel panic when receiving duplicate ASCONF chunks. A remote attacker could use this flaw to crash the system.

CVE-2014-3688

It was found that the sctp stack is prone to a remotely triggerable memory pressure issue caused by excessive queueing. A remote attacker could use this flaw to cause denial-of-service conditions on the system.

CVE-2014-3690

Andy Lutomirski discovered that incorrect register handling in KVM may lead to denial of service.

CVE-2014-7207

Several Debian developers reported an issue in the IPv6 networking subsystem. A local user with access to tun or macvtap devices, or a virtual machine connected to such a device, can cause a denial of service (system crash).

This update includes a bug fix related to CVE-2014-7207 that disables UFO (UDP Fragmentation Offload) in the macvtap, tun, and virtio_net drivers. This will cause migration of a running VM from a host running an earlier kernel version to a host running this kernel version to fail, if the VM has been assigned a virtio network device. In order to migrate such a VM, it must be shut down first.

For the stable distribution (wheezy), these problems have been fixed in version 3.2.63-2+deb7u1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
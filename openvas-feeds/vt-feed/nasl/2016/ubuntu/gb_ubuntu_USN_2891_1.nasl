# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842633");
  script_cve_id("CVE-2015-7549", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8666", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2197", "CVE-2016-2198");
  script_tag(name:"creation_date", value:"2016-02-05 07:44:14 +0000 (Fri, 05 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 14:07:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-2891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2891-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2891-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qinghao Tang discovered that QEMU incorrectly handled PCI MSI-X support. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS
and Ubuntu 15.10. (CVE-2015-7549)

Lian Yihan discovered that QEMU incorrectly handled the VNC server. A
remote attacker could use this issue to cause QEMU to crash, resulting in a
denial of service. (CVE-2015-8504)

Felix Wilhelm discovered a race condition in the Xen paravirtualized
drivers which can cause double fetch vulnerabilities. An attacker in the
paravirtualized guest could exploit this flaw to cause a denial of service
(crash the host) or potentially execute arbitrary code on the host.
(CVE-2015-8550)

Qinghao Tang discovered that QEMU incorrectly handled USB EHCI emulation
support. An attacker inside the guest could use this issue to cause QEMU to
consume resources, resulting in a denial of service. (CVE-2015-8558)

Qinghao Tang discovered that QEMU incorrectly handled the vmxnet3 device.
An attacker inside the guest could use this issue to cause QEMU to consume
resources, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8567, CVE-2015-8568)

Qinghao Tang discovered that QEMU incorrectly handled SCSI MegaRAID SAS HBA
emulation. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8613)

Ling Liu discovered that QEMU incorrectly handled the Human Monitor
Interface. A local attacker could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS
and Ubuntu 15.10. (CVE-2015-8619, CVE-2016-1922)

David Alan Gilbert discovered that QEMU incorrectly handled the Q35 chipset
emulation when performing VM guest migrations. An attacker could use this
issue to cause QEMU to crash, resulting in a denial of service. This issue
only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-8666)

Ling Liu discovered that QEMU incorrectly handled the NE2000 device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2015-8743)

It was discovered that QEMU incorrectly handled the vmxnet3 device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu 14.04 LTS
and Ubuntu 15.10. (CVE-2015-8744, CVE-2015-8745)

Qinghao Tang discovered that QEMU incorrect handled IDE AHCI emulation. An
attacker inside the guest could use this issue to cause a denial of
service, or possibly execute arbitrary code on the host as the user running
the QEMU process. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2016-1568)

Donghai ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

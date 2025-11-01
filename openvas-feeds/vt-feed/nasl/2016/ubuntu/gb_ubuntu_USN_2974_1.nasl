# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842747");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037");
  script_tag(name:"creation_date", value:"2016-05-17 11:39:47 +0000 (Tue, 17 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-2974-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2974-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2974-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-2974-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zuozhi Fzz discovered that QEMU incorrectly handled USB OHCI emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2016-2391)

Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2016-2392)

Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly leak
host memory bytes. (CVE-2016-2538)

Hongke Yang discovered that QEMU incorrectly handled NE2000 emulation
support. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2016-2841)

Ling Liu discovered that QEMU incorrectly handled IP checksum routines. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly leak host memory bytes.
(CVE-2016-2857)

It was discovered that QEMU incorrectly handled the PRNG back-end support.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only applied to Ubuntu 14.04
LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-2858)

Wei Xiao and Qinghao Tang discovered that QEMU incorrectly handled access
in the VGA module. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code on the host. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2016-3710)

Zuozhi Fzz discovered that QEMU incorrectly handled access in the VGA
module. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code on the host. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2016-3712)

Oleksandr Bazhaniuk discovered that QEMU incorrectly handled Luminary
Micro Stellaris ethernet controller emulation. A remote attacker could use
this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2016-4001)

Oleksandr Bazhaniuk discovered that QEMU incorrectly handled MIPSnet
controller emulation. A remote attacker could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2016-4002)

Donghai Zdh discovered that QEMU incorrectly handled the Task Priority
Register(TPR). A privileged attacker inside the guest could use this issue
to possibly leak host memory bytes. This issue only applied to Ubuntu 14.04
LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-4020)

Du Shaobo ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

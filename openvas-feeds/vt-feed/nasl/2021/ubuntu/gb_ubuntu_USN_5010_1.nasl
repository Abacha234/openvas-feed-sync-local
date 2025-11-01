# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844999");
  script_cve_id("CVE-2020-15469", "CVE-2020-29443", "CVE-2020-35504", "CVE-2020-35505", "CVE-2020-35517", "CVE-2021-20221", "CVE-2021-20257", "CVE-2021-3392", "CVE-2021-3409", "CVE-2021-3416", "CVE-2021-3527", "CVE-2021-3544", "CVE-2021-3545", "CVE-2021-3546", "CVE-2021-3582", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3607", "CVE-2021-3608");
  script_tag(name:"creation_date", value:"2021-07-16 03:00:59 +0000 (Fri, 16 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 19:39:00 +0000 (Fri, 04 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5010-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5010-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-5010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lei Sun discovered that QEMU incorrectly handled certain MMIO operations.
An attacker inside the guest could possibly use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2020-15469)

Wenxiang Qian discovered that QEMU incorrectly handled certain ATAPI
commands. An attacker inside the guest could possibly use this issue to
cause QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 21.04. (CVE-2020-29443)

Cheolwoo Myung discovered that QEMU incorrectly handled SCSI device
emulation. An attacker inside the guest could possibly use this issue to
cause QEMU to crash, resulting in a denial of service. (CVE-2020-35504,
CVE-2020-35505, CVE-2021-3392)

Alex Xu discovered that QEMU incorrectly handled the virtio-fs shared file
system daemon. An attacker inside the guest could possibly use this issue
to read and write to host devices. This issue only affected Ubuntu 20.10.
(CVE-2020-35517)

It was discovered that QEMU incorrectly handled ARM Generic Interrupt
Controller emulation. An attacker inside the guest could possibly use this
issue to cause QEMU to crash, resulting in a denial of service. This issue
only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10.
(CVE-2021-20221)

Alexander Bulekov, Cheolwoo Myung, Sergej Schumilo, Cornelius Aschermann,
and Simon Werner discovered that QEMU incorrectly handled e1000 device
emulation. An attacker inside the guest could possibly use this issue to
cause QEMU to hang, resulting in a denial of service. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10.
(CVE-2021-20257)

It was discovered that QEMU incorrectly handled SDHCI controller emulation.
An attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service, or possibly execute arbitrary code. In
the default installation, when QEMU is used in combination with libvirt,
attackers would be isolated by the libvirt AppArmor profile.
(CVE-2021-3409)

It was discovered that QEMU incorrectly handled certain NIC emulation
devices. An attacker inside the guest could possibly use this issue to
cause QEMU to hang or crash, resulting in a denial of service. This issue
only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 20.10.
(CVE-2021-3416)

Remy Noel discovered that QEMU incorrectly handled the USB redirector
device. An attacker inside the guest could possibly use this issue to
cause QEMU to consume resources, resulting in a denial of service.
(CVE-2021-3527)

It was discovered that QEMU incorrectly handled the virtio vhost-user GPU
device. An attacker inside the guest could possibly use this issue to cause
QEMU to consume resources, leading to a denial of service. This issue only
affected Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04. (CVE-2021-3544)

It was discovered that QEMU incorrectly handled the virtio vhost-user GPU
device. An attacker inside ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842845");
  script_cve_id("CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6351");
  script_tag(name:"creation_date", value:"2016-08-08 09:41:56 +0000 (Mon, 08 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 19:19:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3047-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3047-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-3047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Li Qiang discovered that QEMU incorrectly handled 53C9X Fast SCSI
controller emulation. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code on the host. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. This issue only applied to Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-4439, CVE-2016-4441, CVE-2016-5238, CVE-2016-5338, CVE-2016-6351)

Li Qiang and Qinghao Tang discovered that QEMU incorrectly handled the
VMWare VGA module. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service, or possibly
to obtain sensitive host memory. (CVE-2016-4453, CVE-2016-4454)

Li Qiang discovered that QEMU incorrectly handled VMWARE PVSCSI paravirtual
SCSI bus emulation support. A privileged attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of service.
This issue only applied to Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-4952)

Li Qiang discovered that QEMU incorrectly handled MegaRAID SAS 8708EM2 Host
Bus Adapter emulation support. A privileged attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of service, or
possibly to obtain sensitive host memory. This issue only applied to Ubuntu
14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-5105, CVE-2016-5106,
CVE-2016-5107, CVE-2016-5337)

It was discovered that QEMU incorrectly handled certain iSCSI asynchronous
I/O ioctl calls. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service, or possibly execute
arbitrary code on the host. In the default installation, when QEMU is used
with libvirt, attackers would be isolated by the libvirt AppArmor profile.
This issue only applied to Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-5126)

Zhenhao Hong discovered that QEMU incorrectly handled the Virtio module. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2016-5403)");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

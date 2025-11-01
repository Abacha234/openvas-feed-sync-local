# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842944");
  script_cve_id("CVE-2016-5403", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7157", "CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7421", "CVE-2016-7422", "CVE-2016-7423", "CVE-2016-7466", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8668", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");
  script_tag(name:"creation_date", value:"2016-11-14 12:31:13 +0000 (Mon, 14 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:20:00 +0000 (Mon, 16 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-3125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3125-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3125-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu-kvm' package(s) announced via the USN-3125-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhenhao Hong discovered that QEMU incorrectly handled the Virtio module. A
privileged attacker inside the guest could use this issue to cause QEMU to
consume resources, resulting in a denial of service. (CVE-2016-5403)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3 network
card emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-6833, CVE-2016-6834, CVE-2016-6888)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3 network
card emulation support. A privileged attacker inside the guest could use
this issue to cause QEMU to crash, resulting in a denial of service, or
possibly execute arbitrary code on the host. In the default installation,
when QEMU is used with libvirt, attackers would be isolated by the libvirt
AppArmor profile. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
LTS and Ubuntu 16.10. (CVE-2016-6835)

Li Qiang discovered that QEMU incorrectly handled VMWARE VMXNET3 network
card emulation support. A privileged attacker inside the guest could use
this issue to possibly to obtain sensitive host memory. This issue only
affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2016-6836)

Felix Wilhelm discovered that QEMU incorrectly handled Plan 9 File System
(9pfs) support. A privileged attacker inside the guest could use this issue
to possibly to obtain sensitive host files. (CVE-2016-7116)

Li Qiang and Tom Victor discovered that QEMU incorrectly handled VMWARE
PVSCSI paravirtual SCSI bus emulation support. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
LTS and Ubuntu 16.10. (CVE-2016-7155)

Li Qiang discovered that QEMU incorrectly handled VMWARE PVSCSI paravirtual
SCSI bus emulation support. A privileged attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu
16.10. (CVE-2016-7156, CVE-2016-7421)

Tom Victor discovered that QEMU incorrectly handled LSI SAS1068 host bus
emulation support. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.10. (CVE-2016-7157)

Hu Chaojian discovered that QEMU incorrectly handled xlnx.xps-ethernetlite
emulation support. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service, or possibly
execute arbitrary code on the host. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2016-7161)

Qinghao Tang and Li Qiang discovered that QEMU ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu, qemu-kvm' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

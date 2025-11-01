# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891771");
  script_cve_id("CVE-2018-1000026", "CVE-2018-14625", "CVE-2018-16884", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3701", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-8980", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2019-05-04 02:00:21 +0000 (Sat, 04 May 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:00 +0000 (Tue, 05 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-1771)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1771");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1771");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1771 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2018-14625

A use-after-free bug was found in the vhost driver for the Virtual Socket protocol. If this driver is used to communicate with a malicious virtual machine guest, the guest could read sensitive information from the host kernel.

CVE-2018-16884

A flaw was found in the NFS 4.1 client implementation. Mounting NFS shares in multiple network namespaces at the same time could lead to a user-after-free. Local users might be able to use this for denial of service (memory corruption or crash) or possibly for privilege escalation.

This can be mitigated by disabling unprivileged users from creating user namespaces, which is the default in Debian.

CVE-2018-19824

Hui Peng and Mathias Payer discovered a use-after-free bug in the USB audio driver. A physically present attacker able to attach a specially designed USB device could use this for privilege escalation.

CVE-2018-19985

Hui Peng and Mathias Payer discovered a missing bounds check in the hso USB serial driver. A physically present user able to attach a specially designed USB device could use this to read sensitive information from the kernel or to cause a denial of service (crash).

CVE-2018-20169

Hui Peng and Mathias Payer discovered missing bounds checks in the USB core. A physically present attacker able to attach a specially designed USB device could use this to cause a denial of service (crash) or possibly for privilege escalation.

CVE-2018-1000026

It was discovered that Linux could forward aggregated network packets with a segmentation size too large for the output device. In the specific case of Broadcom NetXtremeII 10Gb adapters, this would result in a denial of service (firmware crash). This update adds a mitigation to the bnx2x driver for this hardware.

CVE-2019-3459, CVE-2019-3460 Shlomi Oberman, Yuli Shapiro and Karamba Security Ltd. research team discovered missing range checks in the Bluetooth L2CAP implementation. If Bluetooth is enabled, a nearby attacker could use these to read sensitive information from the kernel.

CVE-2019-3701

Muyu Yu and Marcus Meissner reported that the CAN gateway implementation allowed the frame length to be modified, typically resulting in out-of-bounds memory-mapped I/O writes. On a system with CAN devices present, a local user with CAP_NET_ADMIN capability in the initial net namespace could use this to cause a crash (oops) or other hardware-dependent impact.

CVE-2019-3819

A potential infinite loop was discovered in the HID debugfs interface exposed under /sys/kernel/debug/hid. A user with access to these files could use this for denial of service.

This interface is only accessible to root by default, which fully mitigates the issue.

CVE-2019-6974

Jann Horn reported a use-after-free bug in KVM. A local user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
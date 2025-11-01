# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844111");
  script_cve_id("CVE-2018-20836", "CVE-2019-10142", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-2054", "CVE-2019-9503");
  script_tag(name:"creation_date", value:"2019-07-26 02:00:50 +0000 (Fri, 26 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-29 15:17:00 +0000 (Wed, 29 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-4076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4076-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4076-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-raspi2, linux-signed' package(s) announced via the USN-4076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the Serial Attached SCSI
(SAS) implementation in the Linux kernel. A local attacker could possibly
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2018-20836)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly zero out memory in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2019-11833)

It was discovered that the Bluetooth Human Interface Device Protocol (HIDP)
implementation in the Linux kernel did not properly verify strings were
NULL terminated in certain situations. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-11884)

It was discovered that the Linux kernel on ARM processors allowed a tracing
process to modify a syscall after a seccomp decision had been made on that
syscall. A local attacker could possibly use this to bypass seccomp
restrictions. (CVE-2019-2054)

Hugues Anguelkov discovered that the Broadcom Wifi driver in the Linux
kernel did not properly prevent remote firmware events from being processed
for USB Wifi devices. A physically proximate attacker could use this to
send firmware events to the device. (CVE-2019-9503)

It was discovered that an integer overflow existed in the Freescale
(PowerPC) hypervisor manager in the Linux kernel. A local attacker with
write access to /dev/fsl-hv could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-10142)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-raspi2, linux-signed' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

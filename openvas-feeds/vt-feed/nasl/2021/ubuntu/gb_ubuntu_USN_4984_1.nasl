# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844970");
  script_cve_id("CVE-2021-28038", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28952", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29647", "CVE-2021-30002", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-05 03:00:24 +0000 (Sat, 05 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4984-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4984-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-4984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Beulich discovered that the Xen netback backend in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-28038)

It was discovered that the Realtek RTL8188EU Wireless device driver in the
Linux kernel did not properly validate ssid lengths in some situations. An
attacker could use this to cause a denial of service (system crash).
(CVE-2021-28660)

It was discovered that the Xen paravirtualization backend in the Linux
kernel did not properly deallocate memory in some situations. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2021-28688)

It was discovered that the fuse user space file system implementation in
the Linux kernel did not properly handle bad inodes in some situations. A
local attacker could possibly use this to cause a denial of service.
(CVE-2021-28950)

John Stultz discovered that the audio driver for Qualcomm SDM845 systems in
the Linux kernel did not properly validate port ID numbers. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-28952)

Zygo Blaxell discovered that the btrfs file system implementation in the
Linux kernel contained a race condition during certain cloning operations.
A local attacker could possibly use this to cause a denial of service
(system crash). (CVE-2021-28964)

Vince Weaver discovered that the perf subsystem in the Linux kernel did not
properly handle certain PEBS records properly for some Intel Haswell
processors. A local attacker could use this to cause a denial of service
(system crash). (CVE-2021-28971)

It was discovered that the RPA PCI Hotplug driver implementation in the
Linux kernel did not properly handle device name writes via sysfs, leading
to a buffer overflow. A privileged attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2021-28972)

It was discovered that the Qualcomm IPC router implementation in the Linux
kernel did not properly initialize memory passed to user space. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-29647)

Arnd Bergmann discovered that the video4linux subsystem in the Linux kernel
did not properly deallocate memory in some situations. A local attacker
could use this to cause a denial of service (memory exhaustion).
(CVE-2021-30002)

Dan Carpenter discovered that the block device manager (dm) implementation
in the Linux kernel contained a buffer overflow in the ioctl for listing
devices. A privileged local attacker could use this to cause a denial of
service (system crash). (CVE-2021-31916)

It was discovered that the CIPSO implementation in the Linux kernel did not
properly perform reference counting in some situations, leading to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

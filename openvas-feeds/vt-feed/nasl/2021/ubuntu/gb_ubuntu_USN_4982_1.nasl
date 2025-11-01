# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844966");
  script_cve_id("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2021-28688", "CVE-2021-28950", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29264", "CVE-2021-29647", "CVE-2021-31916", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-06-04 03:00:28 +0000 (Fri, 04 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4982-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4982-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-oracle, linux-oracle-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-4982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25670)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly deallocate memory in certain error
situations. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly handle error conditions in some situations,
leading to an infinite loop. A local attacker could use this to cause a
denial of service. (CVE-2020-25673)

It was discovered that the Xen paravirtualization backend in the Linux
kernel did not properly deallocate memory in some situations. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2021-28688)

It was discovered that the fuse user space file system implementation in
the Linux kernel did not properly handle bad inodes in some situations. A
local attacker could possibly use this to cause a denial of service.
(CVE-2021-28950)

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

It was discovered that the Freescale Gianfar Ethernet driver for the Linux
kernel did not properly handle receive queue overrun when jumbo frames were
enabled in some situations. An attacker could use this to cause a denial of
service (system crash). (CVE-2021-29264)

It was discovered that the Qualcomm IPC router implementation in the Linux
kernel did not properly initialize memory passed to user space. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-29647)

Dan Carpenter discovered that the block device manager (dm) implementation
in the Linux kernel contained a buffer overflow in the ioctl for listing
devices. A privileged local attacker could use this to cause a denial of
service (system crash). (CVE-2021-31916)

Ma Zhe Yu discovered that the IEEE 1394 (Firewire) nosy packet sniffer driver in
the Linux kernel did not properly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-oracle, linux-oracle-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

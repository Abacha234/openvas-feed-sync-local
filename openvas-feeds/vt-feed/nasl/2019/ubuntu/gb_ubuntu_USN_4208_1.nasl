# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844257");
  script_cve_id("CVE-2019-15794", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-18810", "CVE-2019-19048", "CVE-2019-19060", "CVE-2019-19061", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19069", "CVE-2019-19075", "CVE-2019-19083");
  script_tag(name:"creation_date", value:"2019-12-04 03:01:45 +0000 (Wed, 04 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4208-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4208-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-gcp-5.3, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-kvm, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-oracle' package(s) announced via the USN-4208-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the OverlayFS and ShiftFS Drivers in the Linux
kernel did not properly handle reference counting during memory mapping
operations when used in conjunction with AUFS. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-15794)

Nicolas Waisman discovered that the WiFi driver stack in the Linux kernel
did not properly validate SSID lengths. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-17133)

It was discovered that the ARM Komeda display driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-18810)

It was discovered that the VirtualBox guest driver implementation in the
Linux kernel did not properly deallocate memory in certain error
conditions. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-19048)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19060, CVE-2019-19061)

It was discovered that the Intel OPA Gen1 Infiniband Driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19065)

It was discovered that the AMD Audio Coprocessor driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker with the ability to load modules could use this to cause a
denial of service (memory exhaustion). (CVE-2019-19067)

It was discovered in the Qualcomm FastRPC Driver for the Linux kernel did
not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19069)

It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless controller
driver for the Linux kernel did not properly deallocate memory in certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19075)

It was discovered that the AMD Display Engine Driver in the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attack could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19083)

Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the Linux
kernel performed DMA from a kernel stack. A local attacker could use this
to cause a denial of service (system crash). (CVE-2019-17075)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-gcp-5.3, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-kvm, linux-meta-oracle, linux-oracle, linux-signed, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-oracle' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

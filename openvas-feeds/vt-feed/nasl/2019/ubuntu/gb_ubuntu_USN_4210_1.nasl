# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844258");
  script_cve_id("CVE-2019-16746", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-19060", "CVE-2019-19065", "CVE-2019-19075");
  script_tag(name:"creation_date", value:"2019-12-04 03:01:57 +0000 (Wed, 04 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4210-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4210-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow existed in the 802.11 Wi-Fi
configuration interface for the Linux kernel when handling beacon settings.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-16746)

Nicolas Waisman discovered that the WiFi driver stack in the Linux kernel
did not properly validate SSID lengths. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2019-17133)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19060)

It was discovered that the Intel OPA Gen1 Infiniband Driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19065)

It was discovered that the Cascoda CA8210 SPI 802.15.4 wireless controller
driver for the Linux kernel did not properly deallocate memory in certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2019-19075)

Nicolas Waisman discovered that the Chelsio T4/T5 RDMA Driver for the Linux
kernel performed DMA from a kernel stack. A local attacker could use this
to cause a denial of service (system crash). (CVE-2019-17075)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

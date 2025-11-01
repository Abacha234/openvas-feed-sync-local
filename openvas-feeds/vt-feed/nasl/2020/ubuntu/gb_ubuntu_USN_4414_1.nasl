# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844482");
  script_cve_id("CVE-2019-12380", "CVE-2019-16089", "CVE-2019-19036", "CVE-2019-19039", "CVE-2019-19318", "CVE-2019-19377", "CVE-2019-19462", "CVE-2019-19813", "CVE-2019-19816", "CVE-2020-10711", "CVE-2020-12770", "CVE-2020-13143");
  script_tag(name:"creation_date", value:"2020-07-03 03:01:23 +0000 (Fri, 03 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:27:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4414-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4414-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network block device (nbd) implementation in the
Linux kernel did not properly check for error conditions in some
situations. An attacker could possibly use this to cause a denial of service
(system crash). (CVE-2019-16089)

It was discovered that the btrfs file system implementation in the Linux
kernel did not properly validate file system metadata in some situations.
An attacker could use this to construct a malicious btrfs image that, when
mounted, could cause a denial of service (system crash). (CVE-2019-19036,
CVE-2019-19318, CVE-2019-19813, CVE-2019-19816)

It was discovered that the btrfs implementation in the Linux kernel did not
properly detect that a block was marked dirty in some situations. An
attacker could use this to specially craft a file system image that, when
unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly check return values in some situations. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19462)

Matthew Sheets discovered that the SELinux network label handling
implementation in the Linux kernel could be coerced into de-referencing a
NULL pointer. A remote attacker could use this to cause a denial of service
(system crash). (CVE-2020-10711)

It was discovered that the SCSI generic (sg) driver in the Linux kernel did
not properly handle certain error conditions correctly. A local privileged
attacker could use this to cause a denial of service (system crash).
(CVE-2020-12770)

It was discovered that the USB Gadget device driver in the Linux kernel did
not validate arguments passed from configfs in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash) or possibly expose sensitive information. (CVE-2020-13143)

It was discovered that the efi subsystem in the Linux kernel did not handle
memory allocation failures during early boot in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-12380)

It was discovered that the btrfs file system in the Linux kernel in some
error conditions could report register information to the dmesg buffer. A
local attacker could possibly use this to expose sensitive information.
(CVE-2019-19039)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

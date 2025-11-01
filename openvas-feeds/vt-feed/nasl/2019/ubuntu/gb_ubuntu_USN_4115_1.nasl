# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844156");
  script_cve_id("CVE-2018-19985", "CVE-2018-20784", "CVE-2019-0136", "CVE-2019-10207", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284", "CVE-2019-14763", "CVE-2019-15090", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15218", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-3701", "CVE-2019-3819", "CVE-2019-3900", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2019-09-03 02:01:18 +0000 (Tue, 03 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-03 00:15:00 +0000 (Tue, 03 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-4115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4115-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4115-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle' package(s) announced via the USN-4115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hui Peng and Mathias Payer discovered that the Option USB High Speed driver
in the Linux kernel did not properly validate metadata received from the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2018-19985)

Zhipeng Xie discovered that an infinite loop could be triggered in the CFS
Linux kernel process scheduler. A local attacker could possibly use this to
cause a denial of service. (CVE-2018-20784)

It was discovered that the Intel Wi-Fi device driver in the Linux kernel did
not properly validate certain Tunneled Direct Link Setup (TDLS). A
physically proximate attacker could use this to cause a denial of service
(Wi-Fi disconnect). (CVE-2019-0136)

It was discovered that the Bluetooth UART implementation in the Linux
kernel did not properly check for missing tty operations. A local attacker
could use this to cause a denial of service. (CVE-2019-10207)

Amit Klein and Benny Pinkas discovered that the Linux kernel did not
sufficiently randomize IP ID values generated for connectionless networking
protocols. A remote attacker could use this to track particular Linux
devices. (CVE-2019-10638)

Amit Klein and Benny Pinkas discovered that the location of kernel
addresses could be exposed by the implementation of connection-less network
protocols in the Linux kernel. A remote attacker could possibly use this to
assist in the exploitation of another vulnerability in the Linux kernel.
(CVE-2019-10639)

It was discovered that an integer overflow existed in the Linux kernel when
reference counting pages, leading to potential use-after-free issues. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11487)

Jann Horn discovered that a race condition existed in the Linux kernel when
performing core dumps. A local attacker could use this to cause a denial of
service (system crash) or expose sensitive information. (CVE-2019-11599)

It was discovered that a null pointer dereference vulnerability existed in
the LSI Logic MegaRAID driver in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash). (CVE-2019-11810)

It was discovered that the GTCO tablet input driver in the Linux kernel did
not properly bounds check the initial HID report sent by the device. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2019-13631)

Praveen Pandey discovered that the Linux kernel did not properly validate
sent signals in some situations on PowerPC systems with transactional
memory disabled. A local attacker could use this to cause a denial of
service. (CVE-2019-13648)

It was discovered that the floppy driver in the Linux kernel did not
properly validate meta data, leading to a buffer overread. A local attacker
could use this to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-azure, linux-gcp, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-azure, linux-meta-gcp, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844603");
  script_cve_id("CVE-2019-18808", "CVE-2019-19054", "CVE-2019-19061", "CVE-2019-19067", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-9445", "CVE-2020-12888", "CVE-2020-14356", "CVE-2020-16166");
  script_tag(name:"creation_date", value:"2020-09-23 03:00:26 +0000 (Wed, 23 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4526-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4526-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4526-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4526-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the AMD Cryptographic Coprocessor device driver in
the Linux kernel did not properly deallocate memory in some situations. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-18808)

It was discovered that the Conexant 23885 TV card device driver for the
Linux kernel did not properly deallocate memory in some error conditions. A
local attacker could use this to cause a denial of service (memory
exhaustion). (CVE-2019-19054)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19061)

It was discovered that the AMD Audio Coprocessor driver for the Linux
kernel did not properly deallocate memory in certain error conditions. A
local attacker with the ability to load modules could use this to cause a
denial of service (memory exhaustion). (CVE-2019-19067)

It was discovered that the Atheros HTC based wireless driver in the Linux
kernel did not properly deallocate in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19073, CVE-2019-19074)

It was discovered that the F2FS file system in the Linux kernel did not
properly perform bounds checking in some situations, leading to an out-of-
bounds read. A local attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2019-9445)

It was discovered that the VFIO PCI driver in the Linux kernel did not
properly handle attempts to access disabled memory spaces. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2020-12888)

It was discovered that the cgroup v2 subsystem in the Linux kernel did not
properly perform reference counting in some situations, leading to a NULL
pointer dereference. A local attacker could use this to cause a denial of
service or possibly gain administrative privileges. (CVE-2020-14356)

It was discovered that the state of network RNG in the Linux kernel was
potentially observable. A remote attacker could use this to expose
sensitive information. (CVE-2020-16166)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844506");
  script_cve_id("CVE-2019-16089", "CVE-2019-19462", "CVE-2020-11935", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2020-07-23 03:01:27 +0000 (Thu, 23 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-21 06:15:00 +0000 (Fri, 21 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4425-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4425-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4425-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi-5.4, linux-meta-riscv, linux-oracle, linux-raspi-5.4, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-hwe-5.4, linux-signed-oracle' package(s) announced via the USN-4425-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network block device (nbd) implementation in the
Linux kernel did not properly check for error conditions in some
situations. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2019-16089)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly check return values in some situations. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19462)

Mauricio Faria de Oliveira discovered that the aufs implementation in the
Linux kernel improperly managed inode reference counts in the
vfsub_dentry_open() method. A local attacker could use this vulnerability
to cause a denial of service. (CVE-2020-11935)

Jason A. Donenfeld discovered that the ACPI implementation in the Linux
kernel did not properly restrict loading ACPI tables via configfs. A
privileged attacker could use this to bypass Secure Boot lockdown
restrictions and execute arbitrary code in the kernel. (CVE-2020-15780)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gcp, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi-5.4, linux-meta-riscv, linux-oracle, linux-raspi-5.4, linux-riscv, linux-signed, linux-signed-gcp, linux-signed-hwe-5.4, linux-signed-oracle' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845006");
  script_cve_id("CVE-2021-23134", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33909", "CVE-2021-3506");
  script_tag(name:"creation_date", value:"2021-07-21 03:01:03 +0000 (Wed, 21 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:00 +0000 (Thu, 29 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5016-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5016-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.8, linux-azure, linux-azure-5.8, linux-gcp, linux-gcp-5.8, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.8, linux-meta-azure, linux-meta-azure-5.8, linux-meta-gcp, linux-meta-gcp-5.8, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.8, linux-meta-raspi, linux-oracle, linux-oracle-5.8, linux-raspi, linux-signed, linux-signed-azure, linux-signed-azure-5.8, linux-signed-gcp, linux-signed-gcp-5.8, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.8' package(s) announced via the USN-5016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the virtual file system implementation in the Linux
kernel contained an unsigned to signed integer conversion error. A local
attacker could use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2021-33909)

Or Cohen and Nadav Markus discovered a use-after-free vulnerability in the
nfc implementation in the Linux kernel. A privileged local attacker could
use this issue to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-23134)

It was discovered that a race condition in the kernel Bluetooth subsystem
could lead to use-after-free of slab objects. An attacker could use this
issue to possibly execute arbitrary code. (CVE-2021-32399)

It was discovered that a use-after-free existed in the Bluetooth HCI driver
of the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2021-33034)

It was discovered that an out-of-bounds (OOB) memory access flaw existed in
the f2fs module of the Linux kernel. A local attacker could use this issue
to cause a denial of service (system crash). (CVE-2021-3506)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.8, linux-azure, linux-azure-5.8, linux-gcp, linux-gcp-5.8, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.8, linux-meta-azure, linux-meta-azure-5.8, linux-meta-gcp, linux-meta-gcp-5.8, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.8, linux-meta-raspi, linux-oracle, linux-oracle-5.8, linux-raspi, linux-signed, linux-signed-azure, linux-signed-azure-5.8, linux-signed-gcp, linux-signed-gcp-5.8, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.8' package(s) on Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

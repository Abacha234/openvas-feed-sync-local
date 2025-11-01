# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845407");
  script_cve_id("CVE-2021-3772", "CVE-2021-4149", "CVE-2022-1016", "CVE-2022-1419", "CVE-2022-1966", "CVE-2022-21499", "CVE-2022-28356", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-06-09 01:01:19 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:28:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5466-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5466-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5466-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-5466-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly restrict access to
the kernel debugger when booted in secure boot environments. A privileged
attacker could use this to bypass UEFI Secure Boot restrictions.
(CVE-2022-21499)

Aaron Adams discovered that the netfilter subsystem in the Linux kernel did
not properly handle the removal of stateful expressions in some situations,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-1966)

It was discovered that the SCTP protocol implementation in the Linux kernel
did not properly verify VTAGs in some situations. A remote attacker could
possibly use this to cause a denial of service (connection disassociation).
(CVE-2021-3772)

It was discovered that the btrfs file system implementation in the Linux
kernel did not properly handle locking in certain error conditions. A local
attacker could use this to cause a denial of service (kernel deadlock).
(CVE-2021-4149)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

It was discovered that the virtual graphics memory manager implementation
in the Linux kernel was subject to a race condition, potentially leading to
an information leak. (CVE-2022-1419)

Zhao Zi Xuan discovered that the 802.2 LLC type 2 driver in the Linux kernel did not
properly perform reference counting in some error conditions. A local
attacker could use this to cause a denial of service. (CVE-2022-28356)

It was discovered that the EMS CAN/USB interface implementation in the
Linux kernel contained a double-free vulnerability when handling certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2022-28390)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-aws, linux-signed-azure-4.15, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845233");
  script_cve_id("CVE-2020-27820", "CVE-2021-3640", "CVE-2021-3752", "CVE-2021-3772", "CVE-2021-4001", "CVE-2021-4090", "CVE-2021-4093", "CVE-2021-4202", "CVE-2021-42327", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-03 10:10:23 +0000 (Thu, 03 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 01:13:00 +0000 (Tue, 01 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5265-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5265-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.11, linux-aws-5.13, linux-azure-5.11, linux-gcp, linux-gcp-5.11, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.11, linux-meta-aws-5.13, linux-meta-azure-5.11, linux-meta-gcp, linux-meta-gcp-5.11, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oem-5.13, linux-meta-oracle, linux-meta-oracle-5.11, linux-meta-raspi, linux-oem-5.13, linux-oracle, linux-oracle-5.11, linux-raspi, linux-signed, linux-signed-azure-5.11, linux-signed-gcp, linux-signed-gcp-5.11, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oem-5.13, linux-signed-oracle, linux-signed-oracle-5.11' package(s) announced via the USN-5265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jeremy Cline discovered a use-after-free in the nouveau graphics driver of
the Linux kernel during device removal. A privileged or physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-27820)

It was discovered that the Bluetooth subsystem in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2021-3640)

Likang Luo discovered that a race condition existed in the Bluetooth
subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-3752)

It was discovered that the SCTP protocol implementation in the Linux kernel
did not properly verify VTAGs in some situations. A remote attacker could
possibly use this to cause a denial of service (connection disassociation).
(CVE-2021-3772)

It was discovered that the eBPF implementation in the Linux kernel
contained a race condition around read-only maps. A privileged attacker
could use this to modify read-only maps. (CVE-2021-4001)

It was discovered that the NFS server implementation in the Linux kernel
contained an out-of-bounds write vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-4090)

Felix Wilhelm discovered that the KVM implementation in the Linux kernel
did not properly handle exit events from AMD Secure Encrypted
Virtualization-Encrypted State (SEV-ES) guest VMs. An attacker in a guest
VM could use this to cause a denial of service (host kernel crash) or
possibly execute arbitrary code in the host kernel. (CVE-2021-4093)

Lin Ma discovered that the NFC Controller Interface (NCI) implementation in
the Linux kernel contained a race condition, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-4202)

It was discovered that the AMD Radeon GPU driver in the Linux kernel did
not properly validate writes in the debugfs file system. A privileged
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-42327)

Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
did not properly perform bounds checking in some situations. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2021-42739)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.11, linux-aws-5.13, linux-azure-5.11, linux-gcp, linux-gcp-5.11, linux-hwe-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.11, linux-meta-aws-5.13, linux-meta-azure-5.11, linux-meta-gcp, linux-meta-gcp-5.11, linux-meta-hwe-5.13, linux-meta-kvm, linux-meta-oem-5.13, linux-meta-oracle, linux-meta-oracle-5.11, linux-meta-raspi, linux-oem-5.13, linux-oracle, linux-oracle-5.11, linux-raspi, linux-signed, linux-signed-azure-5.11, linux-signed-gcp, linux-signed-gcp-5.11, linux-signed-hwe-5.13, linux-signed-kvm, linux-signed-oem-5.13, linux-signed-oracle, linux-signed-oracle-5.11' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

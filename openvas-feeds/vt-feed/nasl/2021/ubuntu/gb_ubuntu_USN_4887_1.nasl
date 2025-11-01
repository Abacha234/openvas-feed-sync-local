# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844877");
  script_cve_id("CVE-2020-27170", "CVE-2020-27171", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-3444");
  script_tag(name:"creation_date", value:"2021-03-24 04:00:47 +0000 (Wed, 24 Mar 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 19:20:00 +0000 (Thu, 22 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4887-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4887-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4887-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke-5.3, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-oem-5.10, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-oem-5.6, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke-5.3, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.6, linux-signed-oem-5.10, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-4887-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"De4dCr0w of 360 Alpha Lab discovered that the BPF verifier in the Linux
kernel did not properly handle mod32 destination register truncation when
the source register was known to be 0. A local attacker could use this to
expose sensitive information (kernel memory) or possibly execute arbitrary
code. (CVE-2021-3444)

Adam Nichols discovered that heap overflows existed in the iSCSI subsystem
in the Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2021-27365)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly compute a speculative execution limit on pointer arithmetic in
some situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2020-27171)

Piotr Krysiuk discovered that the BPF subsystem in the Linux kernel did not
properly apply speculative execution limits on some pointer types. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2020-27170)

Adam Nichols discovered that the iSCSI subsystem in the Linux kernel did
not properly restrict access to iSCSI transport handles. A local attacker
could use this to cause a denial of service or expose sensitive information
(kernel pointer addresses). (CVE-2021-27363)

Adam Nichols discovered that an out-of-bounds read existed in the iSCSI
subsystem in the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or expose sensitive information (kernel
memory). (CVE-2021-27364)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke-5.3, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-oem-5.10, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-oem-5.6, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke-5.3, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.6, linux-signed-oem-5.10, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

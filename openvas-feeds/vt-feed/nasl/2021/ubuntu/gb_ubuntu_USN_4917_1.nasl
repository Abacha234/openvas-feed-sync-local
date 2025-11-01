# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844901");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-29154", "CVE-2021-3492", "CVE-2021-3493");
  script_tag(name:"creation_date", value:"2021-04-16 03:00:21 +0000 (Fri, 16 Apr 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-31 17:15:00 +0000 (Mon, 31 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4917-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4917-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4917-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke-5.3, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.10, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke-5.3, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.10, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-4917-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the overlayfs implementation in the Linux kernel did
not properly validate the application of file system capabilities with
respect to user namespaces. A local attacker could use this to gain
elevated privileges. (CVE-2021-3493)

Vincent Dehors discovered that the shiftfs file system in the Ubuntu Linux
kernel did not properly handle faults in copy_from_user() when passing
through ioctls to an underlying file system. A local attacker could use
this to cause a denial of service (memory exhaustion) or execute arbitrary
code. (CVE-2021-3492)

Piotr Krysiuk discovered that the BPF JIT compiler for x86 in the Linux
kernel did not properly validate computation of branch displacements in
some situations. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2021-29154)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke-5.3, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke-5.3, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-meta-kvm, linux-meta-oem-5.10, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-oem-5.10, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke-5.3, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8, linux-signed-kvm, linux-signed-oem-5.10, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

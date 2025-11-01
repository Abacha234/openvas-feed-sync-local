# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845199");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-0185");
  script_tag(name:"creation_date", value:"2022-01-20 02:00:21 +0000 (Thu, 20 Jan 2022)");
  script_version("2024-08-23T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 19:18:00 +0000 (Tue, 22 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5240-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5240-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5240-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-aws-5.11, linux-azure, linux-azure-5.4, linux-azure-5.11, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-gcp-5.11, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-aws-5.11, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-5.11, linux-meta-bluefield, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gcp-5.11, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-meta-oem-5.10, linux-meta-oem-5.13, linux-meta-oem-5.14, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-oracle-5.11, linux-meta-raspi, linux-meta-raspi-5.4, linux-oem-5.10, linux-oem-5.13, linux-oem-5.14, linux-oracle, linux-oracle-5.4, linux-oracle-5.11, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-5.11, linux-signed-bluefield, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gcp-5.11, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm, linux-signed-oem-5.10, linux-signed-oem-5.13, linux-signed-oem-5.14, linux-signed-oracle, linux-signed-oracle-5.4, linux-signed-oracle-5.11' package(s) announced via the USN-5240-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"William Liu and Jamie Hill-Daniel discovered that the file system context
functionality in the Linux kernel contained an integer underflow
vulnerability, leading to an out-of-bounds write. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code.");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-aws-5.11, linux-azure, linux-azure-5.4, linux-azure-5.11, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-gcp-5.11, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-aws-5.11, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-5.11, linux-meta-bluefield, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gcp-5.11, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-meta-oem-5.10, linux-meta-oem-5.13, linux-meta-oem-5.14, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-oracle-5.11, linux-meta-raspi, linux-meta-raspi-5.4, linux-oem-5.10, linux-oem-5.13, linux-oem-5.14, linux-oracle, linux-oracle-5.4, linux-oracle-5.11, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-5.11, linux-signed-bluefield, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gcp-5.11, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm, linux-signed-oem-5.10, linux-signed-oem-5.13, linux-signed-oem-5.14, linux-signed-oracle, linux-signed-oracle-5.4, linux-signed-oracle-5.11' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

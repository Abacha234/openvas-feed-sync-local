# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845416");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166");
  script_tag(name:"creation_date", value:"2022-06-18 01:00:26 +0000 (Sat, 18 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 11:15:00 +0000 (Thu, 07 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5485-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5485-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5485-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-aws-5.13, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-azure-5.4, linux-azure-5.13, linux-azure-fde, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-gcp-5.4, linux-gcp-5.13, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.13, linux-ibm, linux-ibm-5.4, linux-intel-5.13, linux-intel-iotg, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-4.15, linux-meta-azure-5.4, linux-meta-azure-5.13, linux-meta-azure-fde, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gcp-5.4, linux-meta-gcp-5.13, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-hwe-5.13, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-intel-5.13, linux-meta-intel-iotg, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-oracle-5.13, linux-oracle, linux-oracle-5.4, linux-oracle-5.13, linux-signed, linux-signed-aws, linux-signed-aws-5.4, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-4.15, linux-signed-azure-5.4, linux-signed-azure-5.13, linux-signed-azure-fde, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gcp-5.4, linux-signed-gcp-5.13, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-hwe-5.13, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-intel-5.13, linux-signed-intel-iotg, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle, linux-signed-oracle-5.4, linux-signed-oracle-5.13' package(s) announced via the USN-5485-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some Intel processors did not completely perform
cleanup actions on multi-core shared buffers. A local attacker could
possibly use this to expose sensitive information. (CVE-2022-21123)

It was discovered that some Intel processors did not completely perform
cleanup actions on microarchitectural fill buffers. A local attacker could
possibly use this to expose sensitive information. (CVE-2022-21125)

It was discovered that some Intel processors did not properly perform
cleanup during specific special register write operations. A local attacker
could possibly use this to expose sensitive information. (CVE-2022-21166)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-aws-5.13, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-azure-5.4, linux-azure-5.13, linux-azure-fde, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-gcp-5.4, linux-gcp-5.13, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe, linux-hwe-5.4, linux-hwe-5.13, linux-ibm, linux-ibm-5.4, linux-intel-5.13, linux-intel-iotg, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-4.15, linux-meta-azure-5.4, linux-meta-azure-5.13, linux-meta-azure-fde, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gcp-5.4, linux-meta-gcp-5.13, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-hwe-5.13, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-intel-5.13, linux-meta-intel-iotg, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-oracle-5.13, linux-oracle, linux-oracle-5.4, linux-oracle-5.13, linux-signed, linux-signed-aws, linux-signed-aws-5.4, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-4.15, linux-signed-azure-5.4, linux-signed-azure-5.13, linux-signed-azure-fde, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gcp-5.4, linux-signed-gcp-5.13, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-hwe-5.13, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-intel-5.13, linux-signed-intel-iotg, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle, linux-signed-oracle-5.4, linux-signed-oracle-5.13' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

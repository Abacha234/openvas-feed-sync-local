# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845271");
  script_cve_id("CVE-2022-0001", "CVE-2022-0002", "CVE-2022-23960", "CVE-2022-25636");
  script_tag(name:"creation_date", value:"2022-03-09 02:00:22 +0000 (Wed, 09 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 17:35:00 +0000 (Fri, 04 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5318-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5318-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5318-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/BHI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-azure-fde, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-bluefield, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-aws, linux-signed-aws-5.4, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-bluefield, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-5318-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Gregory discovered that the Linux kernel incorrectly handled network
offload functionality. A local attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2022-25636)

Enrico Barberis, Pietro Frigo, Marius Muench, Herbert Bos, and Cristiano
Giuffrida discovered that hardware mitigations added by ARM to their
processors to address Spectre-BTI were insufficient. A local attacker could
potentially use this to expose sensitive information. (CVE-2022-23960)

Enrico Barberis, Pietro Frigo, Marius Muench, Herbert Bos, and Cristiano
Giuffrida discovered that hardware mitigations added by Intel to their
processors to address Spectre-BTI were insufficient. A local attacker could
potentially use this to expose sensitive information. (CVE-2022-0001,
CVE-2022-0002)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-azure-fde, linux-bluefield, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-ibm-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-azure-fde, linux-meta-bluefield, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-ibm-5.4, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi-5.4, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-aws, linux-signed-aws-5.4, linux-signed-azure, linux-signed-azure-5.4, linux-signed-azure-fde, linux-signed-bluefield, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-ibm-5.4, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

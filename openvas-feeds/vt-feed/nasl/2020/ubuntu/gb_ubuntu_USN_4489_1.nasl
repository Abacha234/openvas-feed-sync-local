# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844568");
  script_cve_id("CVE-2020-14386");
  script_tag(name:"creation_date", value:"2020-09-09 03:00:19 +0000 (Wed, 09 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4489-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4489-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4489-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.3, linux-aws-5.4, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-azure-5.4, linux-gcp, linux-gcp-4.15, linux-gcp-5.4, linux-gke-4.15, linux-gke-5.0, linux-gke-5.3, linux-hwe, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-aws-5.4, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gcp-5.4, linux-meta-gke-4.15, linux-meta-gke-5.0, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oem, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-meta-snapdragon, linux-oem, linux-oem-osp1, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gcp-5.4, linux-signed-gke-4.15, linux-signed-gke-5.0, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-oem, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.4, linux-snapdragon' package(s) announced via the USN-4489-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Or Cohen discovered that the AF_PACKET implementation in the Linux
kernel did not properly perform bounds checking in some situations. A
local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.3, linux-aws-5.4, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-azure-5.4, linux-gcp, linux-gcp-4.15, linux-gcp-5.4, linux-gke-4.15, linux-gke-5.0, linux-gke-5.3, linux-hwe, linux-hwe-5.4, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-aws-5.4, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gcp-5.4, linux-meta-gke-4.15, linux-meta-gke-5.0, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-kvm, linux-meta-oem, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.4, linux-meta-raspi, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-meta-raspi-5.4, linux-meta-snapdragon, linux-oem, linux-oem-osp1, linux-oracle, linux-oracle-5.4, linux-raspi, linux-raspi2, linux-raspi2-5.3, linux-raspi-5.4, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gcp-5.4, linux-signed-gke-4.15, linux-signed-gke-5.0, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-oem, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.4, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

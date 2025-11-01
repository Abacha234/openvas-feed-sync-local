# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844478");
  script_cve_id("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  script_tag(name:"creation_date", value:"2020-06-26 03:00:16 +0000 (Fri, 26 Jun 2020)");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-13 19:58:00 +0000 (Mon, 13 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4404-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4404-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4404-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.3, linux-azure, linux-azure-5.3, linux-gcp, linux-gcp-5.3, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-azure, linux-meta-azure-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-hwe, linux-meta-oem, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.3, linux-oem, linux-oem-osp1, linux-oracle, linux-oracle-5.3, linux-signed, linux-signed-azure, linux-signed-azure-5.3, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-hwe, linux-signed-oem, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.3' package(s) announced via the USN-4404-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4404-1 fixed vulnerabilities in the NVIDIA graphics drivers.
This update provides the corresponding updates for the NVIDIA Linux
DKMS kernel modules.

Original advisory details:

 Thomas E. Carroll discovered that the NVIDIA Cuda graphics driver did not
 properly perform access control when performing IPC. An attacker could use
 this to cause a denial of service or possibly execute arbitrary code.
 (CVE-2020-5963)

 It was discovered that the UVM driver in the NVIDIA graphics driver
 contained a race condition. A local attacker could use this to cause a
 denial of service. (CVE-2020-5967)

 It was discovered that the NVIDIA virtual GPU guest drivers contained
 an unspecified vulnerability that could potentially lead to privileged
 operation execution. An attacker could use this to cause a denial of
 service. (CVE-2020-5973)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.3, linux-azure, linux-azure-5.3, linux-gcp, linux-gcp-5.3, linux-hwe, linux-meta, linux-meta-aws, linux-meta-aws-5.3, linux-meta-azure, linux-meta-azure-5.3, linux-meta-gcp, linux-meta-gcp-5.3, linux-meta-hwe, linux-meta-oem, linux-meta-oem-osp1, linux-meta-oracle, linux-meta-oracle-5.3, linux-oem, linux-oem-osp1, linux-oracle, linux-oracle-5.3, linux-signed, linux-signed-azure, linux-signed-azure-5.3, linux-signed-gcp, linux-signed-gcp-5.3, linux-signed-hwe, linux-signed-oem, linux-signed-oem-osp1, linux-signed-oracle, linux-signed-oracle-5.3' package(s) on Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

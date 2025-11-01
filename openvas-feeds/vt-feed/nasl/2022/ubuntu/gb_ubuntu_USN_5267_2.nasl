# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845238");
  script_cve_id("CVE-2021-3640", "CVE-2021-3752", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2022-02-09 02:00:41 +0000 (Wed, 09 Feb 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5267-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5267-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5267-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1959665");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-oracle, linux-oracle-5.4, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) announced via the USN-5267-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5267-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
that update introduced a regression that caused the kernel to freeze
when accessing CIFS shares in some situations. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the Bluetooth subsystem in the Linux kernel
 contained a use-after-free vulnerability. A local attacker could use this
 to cause a denial of service (system crash) or possibly execute arbitrary
 code. (CVE-2021-3640)

 Likang Luo discovered that a race condition existed in the Bluetooth
 subsystem of the Linux kernel, leading to a use-after-free vulnerability. A
 local attacker could use this to cause a denial of service (system crash)
 or possibly execute arbitrary code. (CVE-2021-3752)

 Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel
 did not properly perform bounds checking in some situations. A local
 attacker could use this to cause a denial of service (system crash) or
 possibly execute arbitrary code. (CVE-2021-42739)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.4, linux-azure, linux-azure-5.4, linux-gcp, linux-gcp-5.4, linux-gke, linux-gke-5.4, linux-gkeop, linux-gkeop-5.4, linux-hwe-5.4, linux-ibm, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.4, linux-meta-azure, linux-meta-azure-5.4, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-gke, linux-meta-gke-5.4, linux-meta-gkeop, linux-meta-gkeop-5.4, linux-meta-hwe-5.4, linux-meta-ibm, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.4, linux-oracle, linux-oracle-5.4, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-azure-5.4, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-gke, linux-signed-gke-5.4, linux-signed-gkeop, linux-signed-gkeop-5.4, linux-signed-hwe-5.4, linux-signed-ibm, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

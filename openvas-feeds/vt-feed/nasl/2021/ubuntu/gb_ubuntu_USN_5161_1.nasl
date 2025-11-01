# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845146");
  script_cve_id("CVE-2021-3655", "CVE-2021-3744", "CVE-2021-3764", "CVE-2021-42252");
  script_tag(name:"creation_date", value:"2021-12-01 02:00:47 +0000 (Wed, 01 Dec 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-19 01:59:00 +0000 (Tue, 19 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5161-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5161-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5161-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.11, linux-azure, linux-azure-5.11, linux-gcp, linux-gcp-5.11, linux-hwe-5.11, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.11, linux-meta-azure, linux-meta-azure-5.11, linux-meta-gcp, linux-meta-gcp-5.11, linux-meta-hwe-5.11, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.11, linux-meta-raspi, linux-oracle, linux-oracle-5.11, linux-raspi, linux-signed, linux-signed-azure, linux-signed-azure-5.11, linux-signed-gcp, linux-signed-gcp-5.11, linux-signed-hwe-5.11, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.11' package(s) announced via the USN-5161-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja Van Sprundel discovered that the SCTP implementation in the Linux
kernel did not properly perform size validations on incoming packets in
some situations. An attacker could possibly use this to expose sensitive
information (kernel memory). (CVE-2021-3655)

It was discovered that the AMD Cryptographic Coprocessor (CCP) driver in
the Linux kernel did not properly deallocate memory in some error
conditions. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2021-3744, CVE-2021-3764)

It was discovered that the Aspeed Low Pin Count (LPC) Bus Controller
implementation in the Linux kernel did not properly perform boundary checks
in some situations, allowing out-of-bounds write access. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. In Ubuntu, this issue only affected systems running
armhf kernels. (CVE-2021-42252)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.11, linux-azure, linux-azure-5.11, linux-gcp, linux-gcp-5.11, linux-hwe-5.11, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.11, linux-meta-azure, linux-meta-azure-5.11, linux-meta-gcp, linux-meta-gcp-5.11, linux-meta-hwe-5.11, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.11, linux-meta-raspi, linux-oracle, linux-oracle-5.11, linux-raspi, linux-signed, linux-signed-azure, linux-signed-azure-5.11, linux-signed-gcp, linux-signed-gcp-5.11, linux-signed-hwe-5.11, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.11' package(s) on Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

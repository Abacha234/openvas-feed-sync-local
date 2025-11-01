# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845504");
  script_cve_id("CVE-2021-33061", "CVE-2022-1012", "CVE-2022-1729", "CVE-2022-1852", "CVE-2022-1943", "CVE-2022-1973", "CVE-2022-2503", "CVE-2022-2873", "CVE-2022-2959");
  script_tag(name:"creation_date", value:"2022-09-02 01:00:32 +0000 (Fri, 02 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 13:36:00 +0000 (Thu, 11 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5594-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5594-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5594-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.15, linux-azure, linux-azure-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-gkeop, linux-ibm, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-aws-5.15, linux-meta-azure, linux-meta-azure-5.15, linux-meta-gcp, linux-meta-gcp-5.15, linux-meta-gke, linux-meta-gke-5.15, linux-meta-gkeop, linux-meta-ibm, linux-meta-kvm, linux-meta-lowlatency, linux-signed, linux-signed-aws, linux-signed-aws-5.15, linux-signed-azure, linux-signed-azure-5.15, linux-signed-gcp, linux-signed-gcp-5.15, linux-signed-gke, linux-signed-gke-5.15, linux-signed-gkeop, linux-signed-ibm, linux-signed-kvm, linux-signed-lowlatency' package(s) announced via the USN-5594-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asaf Modelevsky discovered that the Intel(R) 10GbE PCI Express (ixgbe)
Ethernet driver for the Linux kernel performed insufficient control flow
management. A local attacker could possibly use this to cause a denial of
service. (CVE-2021-33061)

It was discovered that the IP implementation in the Linux kernel did not
provide sufficient randomization when calculating port offsets. An attacker
could possibly use this to expose sensitive information. (CVE-2022-1012)

Norbert Slusarek discovered that a race condition existed in the perf
subsystem in the Linux kernel, resulting in a use-after-free vulnerability.
A privileged local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-1729)

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered that the KVM hypervisor
implementation in the Linux kernel did not properly handle an illegal
instruction in a guest, resulting in a null pointer dereference. An
attacker in a guest VM could use this to cause a denial of service (system
crash) in the host OS. (CVE-2022-1852)

It was discovered that the UDF file system implementation in the Linux
kernel contained an out-of-bounds write vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-1943)

Gerald Lee discovered that the NTFS file system implementation in the Linux
kernel did not properly handle certain error conditions, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly expose sensitive information.
(CVE-2022-1973)

It was discovered that the device-mapper verity (dm-verity) driver in the
Linux kernel did not properly verify targets being loaded into the device-
mapper table. A privileged attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-2503)

Zheyu Ma discovered that the Intel iSMT SMBus host controller driver in the
Linux kernel contained an out-of-bounds write vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-2873)

Selim Enes Karaduman discovered that a race condition existed in the pipe
buffers implementation of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly escalate
privileges. (CVE-2022-2959)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.15, linux-azure, linux-azure-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-gkeop, linux-ibm, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-aws-5.15, linux-meta-azure, linux-meta-azure-5.15, linux-meta-gcp, linux-meta-gcp-5.15, linux-meta-gke, linux-meta-gke-5.15, linux-meta-gkeop, linux-meta-ibm, linux-meta-kvm, linux-meta-lowlatency, linux-signed, linux-signed-aws, linux-signed-aws-5.15, linux-signed-azure, linux-signed-azure-5.15, linux-signed-gcp, linux-signed-gcp-5.15, linux-signed-gke, linux-signed-gke-5.15, linux-signed-gkeop, linux-signed-ibm, linux-signed-kvm, linux-signed-lowlatency' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

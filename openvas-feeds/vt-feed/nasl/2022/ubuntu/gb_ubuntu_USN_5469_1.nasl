# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845404");
  script_cve_id("CVE-2022-0168", "CVE-2022-1048", "CVE-2022-1158", "CVE-2022-1195", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1263", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-1651", "CVE-2022-1671", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-21499", "CVE-2022-28356", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-06-09 01:00:53 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-11 14:45:00 +0000 (Wed, 11 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5469-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5469-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-ibm, linux-intel-iotg, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke, linux-meta-ibm, linux-meta-intel-iotg, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-gcp, linux-signed-gke, linux-signed-ibm, linux-signed-intel-iotg, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle' package(s) announced via the USN-5469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly restrict access to
the kernel debugger when booted in secure boot environments. A privileged
attacker could use this to bypass UEFI Secure Boot restrictions.
(CVE-2022-21499)

Aaron Adams discovered that the netfilter subsystem in the Linux kernel did
not properly handle the removal of stateful expressions in some situations,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-1966)

Billy Jheng Bing Jhong discovered that the CIFS network file system
implementation in the Linux kernel did not properly validate arguments to
ioctl() in some situations. A local attacker could possibly use this to
cause a denial of service (system crash). (CVE-2022-0168)

Hu Jiahui discovered that multiple race conditions existed in the Advanced
Linux Sound Architecture (ALSA) framework, leading to use-after-free
vulnerabilities. A local attacker could use these to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-1048)

Qiuhao Li, Gaoning Pan and Yongkang Jia discovered that the KVM
implementation in the Linux kernel did not properly perform guest page
table updates in some situations. An attacker in a guest vm could possibly
use this to crash the host OS. (CVE-2022-1158)

It was discovered that the implementation of the 6pack and mkiss protocols
in the Linux kernel did not handle detach events properly in some
situations, leading to a use-after-free vulnerability. A local attacker
could possibly use this to cause a denial of service (system crash).
(CVE-2022-1195)

Duoming Zhou discovered that the 6pack protocol implementation in the Linux
kernel did not handle detach events properly in some situations, leading to
a use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-1198)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

Qiuhao Li, Gaoning Pan, and Yongkang Jia discovered that the kvm
implementation in the Linux kernel did not handle releasing a virtual cpu
properly. A local attacker in a guest VM could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-gke, linux-ibm, linux-intel-iotg, linux-kvm, linux-lowlatency, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke, linux-meta-ibm, linux-meta-intel-iotg, linux-meta-kvm, linux-meta-lowlatency, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed, linux-signed-aws, linux-signed-azure, linux-signed-gcp, linux-signed-gke, linux-signed-ibm, linux-signed-intel-iotg, linux-signed-kvm, linux-signed-lowlatency, linux-signed-oracle' package(s) on Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

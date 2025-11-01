# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845408");
  script_cve_id("CVE-2022-1158", "CVE-2022-1966", "CVE-2022-1972", "CVE-2022-21499", "CVE-2022-24958", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-06-09 01:01:25 +0000 (Thu, 09 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:28:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5468-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5468-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-intel-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-intel-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.13, linux-meta-raspi, linux-oracle, linux-oracle-5.13, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-intel-5.13, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.13' package(s) announced via the USN-5468-1 advisory.");

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

Qiuhao Li, Gaoning Pan and Yongkang Jia discovered that the KVM
implementation in the Linux kernel did not properly perform guest page
table updates in some situations. An attacker in a guest vm could possibly
use this to crash the host OS. (CVE-2022-1158)

Ziming Zhang discovered that the netfilter subsystem in the Linux kernel
did not properly validate sets with multiple ranged fields. A local
attacker could use this to cause a denial of service or execute arbitrary
code. (CVE-2022-1972)

It was discovered that the USB Gadget file system interface in the Linux
kernel contained a use-after-free vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-24958)

It was discovered that the EMS CAN/USB interface implementation in the
Linux kernel contained a double-free vulnerability when handling certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2022-28390)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-5.13, linux-azure, linux-azure-5.13, linux-gcp, linux-gcp-5.13, linux-hwe-5.13, linux-intel-5.13, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-5.13, linux-meta-azure, linux-meta-azure-5.13, linux-meta-gcp, linux-meta-gcp-5.13, linux-meta-hwe-5.13, linux-meta-intel-5.13, linux-meta-kvm, linux-meta-oracle, linux-meta-oracle-5.13, linux-meta-raspi, linux-oracle, linux-oracle-5.13, linux-raspi, linux-signed, linux-signed-aws, linux-signed-aws-5.13, linux-signed-azure, linux-signed-azure-5.13, linux-signed-gcp, linux-signed-gcp-5.13, linux-signed-hwe-5.13, linux-signed-intel-5.13, linux-signed-kvm, linux-signed-oracle, linux-signed-oracle-5.13' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

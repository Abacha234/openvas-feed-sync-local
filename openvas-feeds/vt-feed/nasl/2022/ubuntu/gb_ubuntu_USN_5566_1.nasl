# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845479");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-1652", "CVE-2022-1679", "CVE-2022-2585", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-28893", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5566-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5566-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5566-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-aws-5.15, linux-azure, linux-azure-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-ibm, linux-kvm, linux-meta-aws, linux-meta-aws-5.15, linux-meta-azure, linux-meta-azure-5.15, linux-meta-gcp, linux-meta-gcp-5.15, linux-meta-gke, linux-meta-gke-5.15, linux-meta-ibm, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed-aws, linux-signed-aws-5.15, linux-signed-azure, linux-signed-azure-5.15, linux-signed-gcp, linux-signed-gcp-5.15, linux-signed-gke, linux-signed-gke-5.15, linux-signed-ibm, linux-signed-kvm, linux-signed-oracle' package(s) announced via the USN-5566-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zhenpeng Lin discovered that the network packet scheduler implementation in
the Linux kernel did not properly remove all references to a route filter
before freeing it in some situations. A local attacker could use this to
cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-2588)

It was discovered that the netfilter subsystem of the Linux kernel did not
prevent one nft object from referencing an nft set in another nft table,
leading to a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or execute arbitrary code.
(CVE-2022-2586)

It was discovered that the implementation of POSIX timers in the Linux
kernel did not properly clean up timers in some situations. A local
attacker could use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2022-2585)

Minh Yuan discovered that the floppy disk driver in the Linux kernel
contained a race condition, leading to a use-after-free vulnerability. A
local attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2022-1652)

It was discovered that the Atheros ath9k wireless device driver in the
Linux kernel did not properly handle some error conditions, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-1679)

Felix Fu discovered that the Sun RPC implementation in the Linux kernel did
not properly handle socket states, leading to a use-after-free
vulnerability. A remote attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-28893)

Johannes Wikner and Kaveh Razavi discovered that for some AMD x86-64
processors, the branch predictor could by mis-trained for return
instructions in certain circumstances. A local attacker could possibly use
this to expose sensitive information. (CVE-2022-29900)

Johannes Wikner and Kaveh Razavi discovered that for some Intel x86-64
processors, the Linux kernel's protections against speculative branch
target injection attacks were insufficient in some circumstances. A local
attacker could possibly use this to expose sensitive information.
(CVE-2022-29901)

Arthur Mongodin discovered that the netfilter subsystem in the Linux kernel
did not properly perform data validation. A local attacker could use this
to escalate privileges in certain situations. (CVE-2022-34918)");

  script_tag(name:"affected", value:"'linux-aws, linux-aws-5.15, linux-azure, linux-azure-5.15, linux-gcp, linux-gcp-5.15, linux-gke, linux-gke-5.15, linux-ibm, linux-kvm, linux-meta-aws, linux-meta-aws-5.15, linux-meta-azure, linux-meta-azure-5.15, linux-meta-gcp, linux-meta-gcp-5.15, linux-meta-gke, linux-meta-gke-5.15, linux-meta-ibm, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi, linux-oracle, linux-raspi, linux-signed-aws, linux-signed-aws-5.15, linux-signed-azure, linux-signed-azure-5.15, linux-signed-gcp, linux-signed-gcp-5.15, linux-signed-gke, linux-signed-gke-5.15, linux-signed-ibm, linux-signed-kvm, linux-signed-oracle' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

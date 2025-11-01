# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844910");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-29154", "CVE-2021-3493");
  script_tag(name:"creation_date", value:"2021-04-22 03:02:34 +0000 (Thu, 22 Apr 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4916-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4916-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4916-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1924611");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke-5.3, linux-hwe, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-raspi2-5.3, linux-meta-snapdragon, linux-oem-5.6, linux-raspi2-5.3, linux-signed, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oem-5.6, linux-snapdragon' package(s) announced via the USN-4916-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4916-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
the fix for CVE-2021-3493 introduced a memory leak in some situations.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the overlayfs implementation in the Linux kernel did
 not properly validate the application of file system capabilities with
 respect to user namespaces. A local attacker could use this to gain
 elevated privileges. (CVE-2021-3493)

 Piotr Krysiuk discovered that the BPF JIT compiler for x86 in the Linux
 kernel did not properly validate computation of branch displacements in
 some situations. A local attacker could use this to cause a denial of
 service (system crash) or possibly execute arbitrary code. (CVE-2021-29154)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke-5.3, linux-hwe, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-oem-5.6, linux-meta-raspi2-5.3, linux-meta-snapdragon, linux-oem-5.6, linux-raspi2-5.3, linux-signed, linux-signed-gke-5.3, linux-signed-hwe, linux-signed-oem-5.6, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

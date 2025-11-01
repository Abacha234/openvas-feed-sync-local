# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845191");
  script_cve_id("CVE-2020-26541", "CVE-2021-20321", "CVE-2021-3760", "CVE-2021-4002", "CVE-2021-41864", "CVE-2021-43056", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2022-01-13 02:00:23 +0000 (Thu, 13 Jan 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5210-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5210-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5210-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1956575");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-meta, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-hwe-5.4, linux-signed, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-hwe-5.4' package(s) announced via the USN-5210-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5210-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
that update introduced a regression that caused failures to boot in
environments with AMD Secure Encrypted Virtualization (SEV) enabled.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Nadav Amit discovered that the hugetlb implementation in the Linux kernel
 did not perform TLB flushes under certain conditions. A local attacker
 could use this to leak or alter data from other processes that use huge
 pages. (CVE-2021-4002)

 It was discovered that the Linux kernel did not properly enforce certain
 types of entries in the Secure Boot Forbidden Signature Database (aka dbx)
 protection mechanism. An attacker could use this to bypass UEFI Secure Boot
 restrictions. (CVE-2020-26541)

 It was discovered that a race condition existed in the overlay file system
 implementation in the Linux kernel. A local attacker could use this to
 cause a denial of service (system crash). (CVE-2021-20321)

 It was discovered that the NFC subsystem in the Linux kernel contained a
 use-after-free vulnerability in its NFC Controller Interface (NCI)
 implementation. A local attacker could possibly use this to cause a denial
 of service (system crash) or execute arbitrary code. (CVE-2021-3760)

 It was discovered that an integer overflow could be triggered in the eBPF
 implementation in the Linux kernel when preallocating objects for stack
 maps. A privileged local attacker could use this to cause a denial of
 service or possibly execute arbitrary code. (CVE-2021-41864)

 It was discovered that the KVM implementation for POWER8 processors in the
 Linux kernel did not properly keep track if a wakeup event could be
 resolved by a guest. An attacker in a guest VM could possibly use this to
 cause a denial of service (host OS crash). (CVE-2021-43056)

 It was discovered that the ISDN CAPI implementation in the Linux kernel
 contained a race condition in certain situations that could trigger an
 array out-of-bounds bug. A privileged local attacker could possibly use
 this to cause a denial of service or execute arbitrary code.
 (CVE-2021-43389)");

  script_tag(name:"affected", value:"'linux, linux-gcp, linux-gcp-5.4, linux-hwe-5.4, linux-meta, linux-meta-gcp, linux-meta-gcp-5.4, linux-meta-hwe-5.4, linux-signed, linux-signed-gcp, linux-signed-gcp-5.4, linux-signed-hwe-5.4' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

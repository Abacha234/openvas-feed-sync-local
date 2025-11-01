# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705096");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-29374", "CVE-2020-36322", "CVE-2021-20317", "CVE-2021-20321", "CVE-2021-20322", "CVE-2021-22600", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-28950", "CVE-2021-3640", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38300", "CVE-2021-39685", "CVE-2021-39686", "CVE-2021-39698", "CVE-2021-39713", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4155", "CVE-2021-41864", "CVE-2021-4202", "CVE-2021-4203", "CVE-2021-42739", "CVE-2021-43389", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0322", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-22942", "CVE-2022-24448", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25375");
  script_tag(name:"creation_date", value:"2022-03-10 02:01:05 +0000 (Thu, 10 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5096");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5096");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2020-29374

Jann Horn of Google reported a flaw in Linux's virtual memory management. A parent and child process initially share all their memory, but when either writes to a shared page, the page is duplicated and unshared (copy-on-write). However, in case an operation such as vmsplice() required the kernel to take an additional reference to a shared page, and a copy-on-write occurs during this operation, the kernel might have accessed the wrong process's memory. For some programs, this could lead to an information leak or data corruption.

This issue was already fixed for most architectures, but not on MIPS and System z. This update corrects that.

CVE-2020-36322, CVE-2021-28950 The syzbot tool found that the FUSE (filesystem-in-user-space) implementation did not correctly handle a FUSE server returning invalid attributes for a file. A local user permitted to run a FUSE server could use this to cause a denial of service (crash). The original fix for this introduced a different potential denial of service (infinite loop in kernel space), which has also been fixed.

CVE-2021-3640

Lin Ma discovered a race condition in the Bluetooth protocol implementation that can lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3744, CVE-2021-3764 minihanshen reported bugs in the ccp driver for AMD Cryptographic Coprocessors that could lead to a resource leak. On systems using this driver, a local user could exploit this to cause a denial of service.

CVE-2021-3752

Likang Luo of NSFOCUS Security Team discovered a flaw in the Bluetooth L2CAP implementation that can lead to a user-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2021-3760, CVE-2021-4202 Lin Ma discovered race conditions in the NCI (NFC Controller Interface) driver, which could lead to a use-after-free. A local user could exploit this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. This driver is not enabled in Debian's official kernel configurations.

CVE-2021-3772

A flaw was found in the SCTP protocol implementation, which would allow a networked attacker to break an SCTP association. The attacker would only need to know or guess the IP addresses and ports for the association.

CVE-2021-4002

It was discovered that hugetlbfs, the virtual filesystem used by applications to allocate huge pages in RAM, did not flush the CPU's TLB in one case where it was necessary. In some circumstances a local user would be able to read and write huge pages after they are freed and reallocated to a different process. This could lead to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
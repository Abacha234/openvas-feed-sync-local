# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705050");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-39685", "CVE-2021-4155", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45480", "CVE-2022-0185", "CVE-2022-23222");
  script_tag(name:"creation_date", value:"2022-01-22 02:00:23 +0000 (Sat, 22 Jan 2022)");
  script_version("2024-08-23T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 19:18:00 +0000 (Tue, 22 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5050)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5050");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5050");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5050 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2021-4155

Kirill Tkhai discovered a data leak in the way the XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for a size increase of files with unaligned size. A local attacker can take advantage of this flaw to leak data on the XFS filesystem.

CVE-2021-28711, CVE-2021-28712, CVE-2021-28713 (XSA-391) Juergen Gross reported that malicious PV backends can cause a denial of service to guests being serviced by those backends via high frequency events, even if those backends are running in a less privileged environment.

CVE-2021-28714, CVE-2021-28715 (XSA-392) Juergen Gross discovered that Xen guests can force the Linux netback driver to hog large amounts of kernel memory, resulting in denial of service.

CVE-2021-39685

Szymon Heidrich discovered a buffer overflow vulnerability in the USB gadget subsystem, resulting in information disclosure, denial of service or privilege escalation.

CVE-2021-45095

It was discovered that the Phone Network protocol (PhoNet) driver has a reference count leak in the pep_sock_accept() function.

CVE-2021-45469

Wenqing Liu reported an out-of-bounds memory access in the f2fs implementation if an inode has an invalid last xattr entry. An attacker able to mount a specially crafted image can take advantage of this flaw for denial of service.

CVE-2021-45480

A memory leak flaw was discovered in the __rds_conn_create() function in the RDS (Reliable Datagram Sockets) protocol subsystem.

CVE-2022-0185

William Liu, Jamie Hill-Daniel, Isaac Badipe, Alec Petridis, Hrvoje Misetic and Philip Papurt discovered a heap-based buffer overflow flaw in the legacy_parse_param function in the Filesystem Context functionality, allowing an local user (with CAP_SYS_ADMIN capability in the current namespace) to escalate privileges.

CVE-2022-23222

tr3e discovered that the BPF verifier does not properly restrict several *_OR_NULL pointer types allowing these types to do pointer arithmetic. A local user with the ability to call bpf(), can take advantage of this flaw to excalate privileges. Unprivileged calls to bpf() are disabled by default in Debian, mitigating this flaw.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.92-1. This version includes changes which were aimed to land in the next Debian bullseye point release.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
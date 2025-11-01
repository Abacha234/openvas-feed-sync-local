# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705161");
  script_cve_id("CVE-2022-0494", "CVE-2022-0854", "CVE-2022-1012", "CVE-2022-1729", "CVE-2022-1786", "CVE-2022-1789", "CVE-2022-1852", "CVE-2022-1974", "CVE-2022-1975", "CVE-2022-2078", "CVE-2022-21499", "CVE-2022-28893", "CVE-2022-32250");
  script_tag(name:"creation_date", value:"2022-06-14 01:00:21 +0000 (Tue, 14 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:00 +0000 (Fri, 30 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5161)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5161");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5161");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-5161 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2022-0494

The scsi_ioctl() was susceptible to an information leak only exploitable by users with CAP_SYS_ADMIN or CAP_SYS_RAWIO capabilities.

CVE-2022-0854

Ali Haider discovered a potential information leak in the DMA subsystem. On systems where the swiotlb feature is needed, this might allow a local user to read sensitive information.

CVE-2022-1012

The randomisation when calculating port offsets in the IP implementation was enhanced.

CVE-2022-1729

Norbert Slusarek discovered a race condition in the perf subsystem which could result in local privilege escalation to root. The default settings in Debian prevent exploitation unless more permissive settings have been applied in the kernel.perf_event_paranoid sysctl.

CVE-2022-1786

Kyle Zeng discovered a use-after-free in the io_uring subsystem which way result in local privilege escalation to root.

CVE-2022-1789 / CVE-2022-1852 Yongkang Jia, Gaoning Pan and Qiuhao Li discovered two NULL pointer dereferences in KVM's CPU instruction handling, resulting in denial of service.

CVE-2022-32250

Aaron Adams discovered a use-after-free in Netfilter which may result in local privilege escalation to root.

CVE-2022-1974 / CVE-2022-1975 Duoming Zhou discovered that the NFC netlink interface was suspectible to denial of service.

CVE-2022-2078

Ziming Zhang discovered an out-of-bound write in Netfilter which may result in local privilege escalation to root.

CVE-2022-21499

It was discovered that the kernel debugger could be used to bypass UEFI Secure Boot restrictions.

CVE-2022-28893

Felix Fu discovered a use-after-free in the implementation of the Remote Procedure Call (SunRPC) protocol, which could result in denial of service or an information leak.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.120-1.

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
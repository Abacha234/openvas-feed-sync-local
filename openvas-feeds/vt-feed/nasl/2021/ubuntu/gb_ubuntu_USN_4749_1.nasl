# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844848");
  script_cve_id("CVE-2020-25669", "CVE-2020-27815", "CVE-2020-27830", "CVE-2020-28941", "CVE-2020-29374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661");
  script_tag(name:"creation_date", value:"2021-02-26 04:00:48 +0000 (Fri, 26 Feb 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4749-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4749-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4749-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4749-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bodong Zhao discovered a use-after-free in the Sun keyboard driver
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service or possibly execute arbitrary code.
(CVE-2020-25669)

It was discovered that the jfs file system implementation in the Linux
kernel contained an out-of-bounds read vulnerability. A local attacker
could use this to possibly cause a denial of service (system crash).
(CVE-2020-27815)

Shisong Qin and Bodong Zhao discovered that Speakup screen reader driver in
the Linux kernel did not correctly handle setting line discipline in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2020-27830, CVE-2020-28941)

It was discovered that the memory management subsystem in the Linux kernel
did not properly handle copy-on-write operations in some situations. A
local attacker could possibly use this to gain unintended write access to
read-only memory pages. (CVE-2020-29374)

Michael Kurth and Pawel Wieczorkiewicz discovered that the Xen event
processing backend in the Linux kernel did not properly limit the number of
events queued. An attacker in a guest VM could use this to cause a denial
of service in the host OS. (CVE-2020-29568)

Olivier Benjamin and Pawel Wieczorkiewicz discovered a race condition the
Xen paravirt block backend in the Linux kernel, leading to a use-after-free
vulnerability. An attacker in a guest VM could use this to cause a denial
of service in the host OS. (CVE-2020-29569)

Jann Horn discovered that the tty subsystem of the Linux kernel did not use
consistent locking in some situations, leading to a read-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly expose sensitive information (kernel memory).
(CVE-2020-29660)

Jann Horn discovered a race condition in the tty subsystem of the Linux
kernel in the locking for the TIOCSPGRP ioctl(), leading to a use-after-
free vulnerability. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2020-29661)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-gke-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp, linux-meta-gcp-4.15, linux-meta-gke-4.15, linux-meta-hwe, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp, linux-signed-gcp-4.15, linux-signed-gke-4.15, linux-signed-hwe, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

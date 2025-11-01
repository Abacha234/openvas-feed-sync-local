# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844410");
  script_cve_id("CVE-2019-16234", "CVE-2019-19768", "CVE-2020-10942", "CVE-2020-11884", "CVE-2020-8648", "CVE-2020-8992", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2020-04-29 03:01:12 +0000 (Wed, 29 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 22:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4342-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4342-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-gke-5.3, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-raspi2, linux-raspi2-5.3, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-5.3, linux-signed-hwe' package(s) announced via the USN-4342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Al Viro discovered that the Linux kernel for s390x systems did not properly
perform page table upgrades for kernel sections that use secondary address
mode. A local attacker could use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2020-11884)

It was discovered that the Intel Wi-Fi driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash).
(CVE-2019-16234)

Tristan Madani discovered that the block I/O tracing implementation in the
Linux kernel contained a race condition. A local attacker could use this to
cause a denial of service (system crash) or possibly expose sensitive
information. (CVE-2019-19768)

It was discovered that the vhost net driver in the Linux kernel contained a
stack buffer overflow. A local attacker with the ability to perform ioctl()
calls on /dev/vhost-net could use this to cause a denial of service (system
crash). (CVE-2020-10942)

It was discovered that the virtual terminal implementation in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service (system crash) or expose sensitive
information. (CVE-2020-8648)

Shijie Luo discovered that the ext4 file system implementation in the Linux
kernel did not properly check for a too-large journal size. An attacker
could use this to construct a malicious ext4 image that, when mounted,
could cause a denial of service (soft lockup). (CVE-2020-8992)

Jordy Zomer discovered that the floppy driver in the Linux kernel did not
properly check for errors in some situations. A local attacker could
possibly use this to cause a denial of service (system crash) or possibly
expose sensitive information. (CVE-2020-9383)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-gke-5.3, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-kvm, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-raspi2, linux-raspi2-5.3, linux-signed, linux-signed-azure, linux-signed-gcp, linux-signed-gke-5.3, linux-signed-hwe' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

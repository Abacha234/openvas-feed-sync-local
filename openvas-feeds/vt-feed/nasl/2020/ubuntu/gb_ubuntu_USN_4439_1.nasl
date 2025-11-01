# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844514");
  script_cve_id("CVE-2019-12380", "CVE-2019-16089", "CVE-2019-19036", "CVE-2019-19462", "CVE-2019-20810", "CVE-2019-20908", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-11935", "CVE-2020-13974", "CVE-2020-15780");
  script_tag(name:"creation_date", value:"2020-07-28 03:00:36 +0000 (Tue, 28 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 23:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4439-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4439-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke-5.0, linux-meta-gke-5.0, linux-meta-oem-osp1, linux-oem-osp1, linux-signed-gke-5.0, linux-signed-oem-osp1' package(s) announced via the USN-4439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the network block device (nbd) implementation in the
Linux kernel did not properly check for error conditions in some
situations. An attacker could possibly use this to cause a denial of
service (system crash). (CVE-2019-16089)

It was discovered that the btrfs file system implementation in the Linux
kernel did not properly validate file system metadata in some situations.
An attacker could use this to construct a malicious btrfs image that, when
mounted, could cause a denial of service (system crash). (CVE-2019-19036)

It was discovered that the kernel->user space relay implementation in the
Linux kernel did not properly check return values in some situations. A
local attacker could possibly use this to cause a denial of service (system
crash). (CVE-2019-19462)

Chuhong Yuan discovered that go7007 USB audio device driver in the Linux
kernel did not properly deallocate memory in some failure conditions. A
physically proximate attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2019-20810)

It was discovered that the elf handling code in the Linux kernel did not
initialize memory before using it in certain situations. A local attacker
could use this to possibly expose sensitive information (kernel memory).
(CVE-2020-10732)

Fan Yang discovered that the mremap implementation in the Linux kernel did
not properly handle DAX Huge Pages. A local attacker with access to DAX
storage could use this to gain administrative privileges. (CVE-2020-10757)

It was discovered that the Linux kernel did not correctly apply Speculative
Store Bypass Disable (SSBD) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10766)

It was discovered that the Linux kernel did not correctly apply Indirect
Branch Predictor Barrier (IBPB) mitigations in certain situations. A local
attacker could possibly use this to expose sensitive information.
(CVE-2020-10767)

It was discovered that the Linux kernel could incorrectly enable Indirect
Branch Speculation after it has been disabled for a process via a prctl()
call. A local attacker could possibly use this to expose sensitive
information. (CVE-2020-10768)

Mauricio Faria de Oliveira discovered that the aufs implementation in the
Linux kernel improperly managed inode reference counts in the
vfsub_dentry_open() method. A local attacker could use this vulnerability
to cause a denial of service. (CVE-2020-11935)

It was discovered that the Virtual Terminal keyboard driver in the Linux
kernel contained an integer overflow. A local attacker could possibly use
this to have an unspecified impact. (CVE-2020-13974)

It was discovered that the efi subsystem in the Linux kernel did not handle
memory allocation failures during early boot in some situations. A local
attacker could possibly use this to cause a denial of service (system
crash). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-gke-5.0, linux-meta-gke-5.0, linux-meta-oem-osp1, linux-oem-osp1, linux-signed-gke-5.0, linux-signed-oem-osp1' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

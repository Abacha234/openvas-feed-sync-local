# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843576");
  script_cve_id("CVE-2018-1094", "CVE-2018-10940", "CVE-2018-1095", "CVE-2018-11508", "CVE-2018-7755");
  script_tag(name:"creation_date", value:"2018-07-03 03:48:14 +0000 (Tue, 03 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 10:30:00 +0000 (Wed, 31 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3695-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3695-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oem, linux-meta-raspi2, linux-oem, linux-raspi2' package(s) announced via the USN-3695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly initialize the crc32c checksum driver. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2018-1094)

It was discovered that the cdrom driver in the Linux kernel contained an
incorrect bounds check. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2018-10940)

Wen Xu discovered that the ext4 file system implementation in the Linux
kernel did not properly validate xattr sizes. A local attacker could use
this to cause a denial of service (system crash). (CVE-2018-1095)

Jann Horn discovered that the 32 bit adjtimex() syscall implementation for
64 bit Linux kernels did not properly initialize memory returned to user
space in some situations. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-11508)

It was discovered that an information leak vulnerability existed in the
floppy driver in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2018-7755)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-oem, linux-meta-raspi2, linux-oem, linux-raspi2' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

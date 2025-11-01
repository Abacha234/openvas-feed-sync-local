# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887226");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-1298");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-11 04:08:08 +0000 (Tue, 11 Jun 2024)");
  script_name("Fedora: Security Advisory for efifs (FEDORA-2024-69933b0732)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-69933b0732");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/F7NUL7NSZQ76A5OKDUCODQNY7WSX4SST");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'efifs'
  package(s) announced via the FEDORA-2024-69933b0732 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Free software EFI/UEFI standalone file system drivers, based on the GRUB 2.0
read-only drivers: AFFS (Amiga Fast FileSystem), BFS (BeOS FileSystem), btrfs,
exFAT, ext2/ext3/ext4, F2FS (experimental), HFS and HFS+ (Mac OS, including
the compression support), ISO9660, JFS (Journaled FileSystem), nilfs2, NTFS
(including compression support), ReiserFS, SFS (Amiga Smart FileSystem), UDF,
UFS/FFS, UFS2/FFS2, XFS, ZFS and more.");

  script_tag(name:"affected", value:"'efifs' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);

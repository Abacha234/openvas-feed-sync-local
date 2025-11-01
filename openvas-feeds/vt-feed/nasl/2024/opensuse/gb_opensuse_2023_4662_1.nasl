# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833770");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-3638", "CVE-2023-3180", "CVE-2023-3354");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-20 12:58:14 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:21:10 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2023:4662-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4662-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4F4KU4ZSTABH27Y56B5B4HPVK3FVN5M2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2023:4662-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2021-3638: hw/display/ati_2d: Fix buffer overflow in ati_2d_blt
      (bsc#1188609)

  * CVE-2023-3180: virtio-crypto: verify src and dst buffer length for sym
      request (bsc#1213925)

  * CVE-2023-3354: io: remove io watch if TLS channel is closed during handshake
      (bsc#1212850)

  * [openSUSE] roms/ipxe: Backport 0aa2e4ec9635, in preparation of binutils 2.41
      (bsc#1215311)

  * target/s390x: Fix the 'ignored match' case in VSTRS (bsc#1213210)

  * linux-user/elfload: Enable vxe2 on s390x (bsc#1213210)

  ##");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833306");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-3638", "CVE-2021-3750", "CVE-2023-0330", "CVE-2023-3180", "CVE-2023-3354");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 18:14:14 +0000 (Mon, 16 May 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:59:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2023:4056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4056-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/L5JTEJWBKWTQX55KH4CVHSPA5CEHEHUR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2023:4056-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2023-3180: Fixed a buffer overflow in the virtio-crypto device
      (bsc#1213925).

  * CVE-2021-3750: Fixed a DMA reentrancy in the USB EHCI device that could lead
      to use-after-free (bsc#1190011).

  * CVE-2021-3638: Fixed a buffer overflow in the ati-vga device (bsc#1188609).

  * CVE-2023-3354: Fixed an issue when performing a TLS handshake that could
      lead to remote denial of service via VNC connection (bsc#1212850).

  * CVE-2023-0330: Fixed a DMA reentrancy issue in the lsi53c895a device that
      could lead to a stack overflow (bsc#1207205).

  Non-security fixes:

  * Fixed a potential build issue in the librm subcomponent (bsc#1215311).

  * Fixed a potential crash during VM migration (bsc#1213663).

  * Fixed potential issues during installation on a Xen host (bsc#1179993,
      bsc#1181740).

  ##");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

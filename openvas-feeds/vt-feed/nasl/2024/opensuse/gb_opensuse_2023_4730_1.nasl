# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833706");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-2006", "CVE-2023-25775", "CVE-2023-39197", "CVE-2023-39198", "CVE-2023-4244", "CVE-2023-45863", "CVE-2023-45871", "CVE-2023-46862", "CVE-2023-5158", "CVE-2023-5633", "CVE-2023-5717", "CVE-2023-6039", "CVE-2023-6176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:37 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:4730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4730-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RXQR37WTEBMAT2NTFW7M7K2ITZDYTBBU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:4730-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-6176: Fixed a denial of service in the cryptographic algorithm
      scatterwalk functionality (bsc#1217332).

  * CVE-2023-2006: Fixed a race condition in the RxRPC network protocol
      (bsc#1210447).

  * CVE-2023-5633: Fixed a use-after-free flaw in the way memory objects were
      handled when they were being used to store a surface (bsc#1216527).

  * CVE-2023-39197: Fixed a out-of-bounds read in nf_conntrack_dccp_packet()
      (bsc#1216976).

  * CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which
      could be exploited to achieve local privilege escalation (bsc#1215420).

  * CVE-2023-6039: Fixed a use-after-free in lan78xx_disconnect in
      drivers/net/usb/lan78xx.c (bsc#1217068).

  * CVE-2023-45863: Fixed a out-of-bounds write in fill_kobj_path()
      (bsc#1216058).

  * CVE-2023-5158: Fixed a denial of service in vringh_kiov_advance() in
      drivers/vhost/vringh.c in the host side of a virtio ring (bsc#1215710).

  * CVE-2023-45871: Fixed an issue in the IGB driver, where the buffer size may
      not be adequate for frames larger than the MTU (bsc#1216259).

  * CVE-2023-5717: Fixed a heap out-of-bounds write vulnerability in the
      Performance Events component (bsc#1216584).

  * CVE-2023-39198: Fixed a race condition leading to use-after-free in
      qxl_mode_dumb_create() (bsc#1216965).

  * CVE-2023-25775: Fixed improper access control in the Intel Ethernet
      Controller RDMA driver (bsc#1216959).

  * CVE-2023-46862: Fixed a NULL pointer dereference in io_uring_show_fdinfo()
      (bsc#1216693).

  The following non-security bugs were fixed:

  * ACPI: FPDT: properly handle invalid FPDT subtables (git-fixes).

  * ACPI: resource: Do IRQ override on TongFang GMxXGxx (git-fixes).

  * ACPI: resource: Skip IRQ override on ASUS ExpertBook B1402CVA (git-fixes).

  * ACPI: sysfs: Fix create_pnp_modalias() and create_of_modalias() (git-fixes).

  * ALSA: hda/realtek - ALC287 Realtek I2S speaker platform support (git-fixes).

  * ALSA: hda/realtek - Add Dell ALC295 to pin fall back table (git-fixes).

  * ALSA: hda/realtek - Enable internal speaker of ASUS K6500ZC (git-fixes).

  * ALSA: hda/realtek: Add quirk for ASUS UX7602ZM (git-fixes).

  * ALSA: hda/realtek: Add quirks for ASUS 2024 Zenbooks (git-fixes).

  * ALSA: hda/realtek: Add quirks for HP Laptops (git-fixes).

  * ALSA: hda/realtek: Add support dual speaker for Dell (git-fixes).

  * ALSA ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

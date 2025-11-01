# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833023");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1249", "CVE-2023-1829", "CVE-2023-2430", "CVE-2023-28866", "CVE-2023-3090", "CVE-2023-3111", "CVE-2023-3212", "CVE-2023-3220", "CVE-2023-3357", "CVE-2023-3358", "CVE-2023-3389", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35828", "CVE-2023-35829");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:04:26 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:2892-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2892-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UOULOLHQ5CAPMM7K7SUOL7J6IT4HAE5F");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:2892-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various
  security and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that
      allowed a local user to crash the system (bsc#1209039).

  * CVE-2023-1829: Fixed a use-after-free vulnerability in the control index
      filter (tcindex) (bsc#1210335).

  * CVE-2023-2430: Fixed a possible denial of service via a missing lock in the
      io_uring subsystem (bsc#1211014).

  * CVE-2023-28866: Fixed an out-of-bounds access in net/bluetooth/hci_sync.c
      because amp_init1[] and amp_init2[] are supposed to have an intentionally
      invalid element, but did not (bsc#1209780).

  * CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver
      (bsc#1212842).

  * CVE-2023-3111: Fixed a use-after-free vulnerability in prepare_to_relocate
      in fs/btrfs/relocation.c (bsc#1212051).

  * CVE-2023-3212: Fixed a NULL pointer dereference flaw in the gfs2 file system
      (bsc#1212265).

  * CVE-2023-3220: Fixed a NULL pointer dereference flaw in
      dpu_crtc_atomic_check in drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.c lacks
      check of the return value of kzalloc() (bsc#1212556).

  * CVE-2023-3357: Fixed a NULL pointer dereference flaw in the AMD Sensor
      Fusion Hub driver (bsc#1212605).

  * CVE-2023-3358: Fixed a NULL pointer dereference flaw in the Integrated
      Sensor Hub (ISH) driver (bsc#1212606).

  * CVE-2023-3389: Fixed a use-after-free vulnerability in the io_uring
      subsystem (bsc#1212838).

  * CVE-2023-35788: Fixed an out-of-bounds write in the flower classifier code
      via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets in fl_set_geneve_opt in
      net/sched/cls_flower.c (bsc#1212504).

  * CVE-2023-35823: Fixed a use-after-free flaw in saa7134_finidev in
      drivers/media/pci/saa7134/saa7134-core.c (bsc#1212494).

  * CVE-2023-35828: Fixed a use-after-free flaw in renesas_usb3_remove in
      drivers/usb/gadget/udc/renesas_usb3.c (bsc#1212513).

  * CVE-2023-35829: Fixed a use-after-free flaw in rkvdec_remove in
      drivers/staging/media/rkvdec/rkvdec.c (bsc#1212495).

  The following non-security bugs were fixed:

  * ACPI: CPPC: Add AMD pstate energy performance preference cppc control
      (bsc#1212445).

  * ACPI: CPPC: Add auto select register read/write support (bsc#1212445).

  * ACPI: sleep: Avoid breaking S3 wakeup due to might_sleep() (git-fixes).

  * ALSA: ac97: Fix possible NULL dereference in snd_ac97_mixer (git-fixes).

  * ALSA: fireface: make re ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

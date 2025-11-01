# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833490");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-21400", "CVE-2023-2156", "CVE-2023-2166", "CVE-2023-31083", "CVE-2023-3268", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-38409", "CVE-2023-3863", "CVE-2023-4004");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 17:08:39 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:17:19 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:3311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3311-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VK64IQ3ASLSFK5ARM3HLTYZ6IUVCEO66");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:3311-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2022-40982: Fixed transient execution attack called 'Gather Data
      Sampling' (bsc#1206418).

  * CVE-2023-0459: Fixed information leak in __uaccess_begin_nospec
      (bsc#1211738).

  * CVE-2023-20569: Fixed side channel attack Inception or RAS Poisoning
      (bsc#1213287).

  * CVE-2023-21400: Fixed several memory corruptions due to improper locking in
      io_uring (bsc#1213272).

  * CVE-2023-2156: Fixed a flaw in the networking subsystem within the handling
      of the RPL protocol (bsc#1211131).

  * CVE-2023-2166: Fixed NULL pointer dereference in can_rcv_filter
      (bsc#1210627).

  * CVE-2023-31083: Fixed race condition in hci_uart_tty_ioctl (bsc#1210780).

  * CVE-2023-3268: Fixed an out of bounds memory access flaw in
      relay_file_read_start_pos in the relayfs (bsc#1212502).

  * CVE-2023-3567: Fixed a use-after-free in vcs_read in
      drivers/tty/vt/vc_screen.c (bsc#1213167).

  * CVE-2023-3609: Fixed reference counter leak leading to overflow in net/sched
      (bsc#1213586).

  * CVE-2023-3611: Fixed an out-of-bounds write in net/sched
      sch_qfq(bsc#1213585).

  * CVE-2023-3776: Fixed improper refcount update in cls_fw leads to use-after-
      free (bsc#1213588).

  * CVE-2023-38409: Fixed an issue in set_con2fb_map in
      drivers/video/fbdev/core/fbcon.c. Because an assignment occurs only for the
      first vc, the fbcon_registered_fb and fbcon_display arrays can be
      desynchronized in fbcon_mode_deleted (the con2fb_map points at the old
      fb_info) (bsc#1213417).

  * CVE-2023-3863: Fixed a use-after-free flaw in nfc_llcp_find_local in
      net/nfc/llcp_core.c in NFC. This flaw allowed a local user with special
      privileges to impact a kernel information leak issue (bsc#1213601).

  * CVE-2023-4004: Fixed improper element removal netfilter nft_set_pipapo
      (bsc#1213812).

  The following non-security bugs were fixed:

  * ACPI: CPPC: Add ACPI disabled check to acpi_cpc_valid() (bsc#1212445).

  * ACPI: CPPC: Add definition for undefined FADT preferred PM profile value
      (bsc#1212445).

  * ACPI/IORT: Remove erroneous id_count check in iort_node_get_rmr_info() (git-
      fixes).

  * ACPI: utils: Fix acpi_evaluate_dsm_typed() redefinition error (git-fixes).

  * afs: Adjust ACK interpretation to try and cope with NAT (git-fixes).

  * afs: Fix access after dec in put functions (git-fixes).

  * afs: Fix afs_getattr() to refetch file st ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

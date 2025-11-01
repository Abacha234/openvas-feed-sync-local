# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833163");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-21400", "CVE-2023-2156", "CVE-2023-2166", "CVE-2023-31083", "CVE-2023-3268", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776", "CVE-2023-4004");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 17:08:39 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:49:06 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:3313-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3313-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PLT27M7IMBV37EDNRSXVN425Y7YFDQO7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:3313-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
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

  * CVE-2023-4004: Fixed improper element removal netfilter nft_set_pipapo
      (bsc#1213812).

  The following non-security bugs were fixed:

  * afs: Fix access after dec in put functions (git-fixes).

  * afs: Fix afs_getattr() to refetch file status if callback break occurred
      (git-fixes).

  * afs: Fix dynamic root getattr (git-fixes).

  * afs: Fix fileserver probe RTT handling (git-fixes).

  * afs: Fix infinite loop found by xfstest generic/676 (git-fixes).

  * afs: Fix lost servers_outstanding count (git-fixes).

  * afs: Fix server- active leak in afs_put_server (git-fixes).

  * afs: Fix setting of mtime when creating a file/dir/symlink (git-fixes).

  * afs: Fix updating of i_size with dv jump from server (git-fixes).

  * afs: Fix vlserver probe RTT handling (git-fixes).

  * afs: Return -EAGAIN, not -EREMOTEIO, when a file already locked (git-fixes).

  * afs: Use refcount_t rather than atomic_t (git-fixes).

  * afs: Use the operation issue time instead of the reply time for callbacks
      (git-fixes).

  * afs: adjust ack interpretation to try and cope with nat (git-fixes).

  * alsa: emu10k1: roll up loops in dsp setup c ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

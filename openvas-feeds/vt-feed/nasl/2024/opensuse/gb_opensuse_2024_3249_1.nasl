# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856480");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-4441", "CVE-2022-0854", "CVE-2022-20368", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-48686", "CVE-2022-48775", "CVE-2022-48778", "CVE-2022-48787", "CVE-2022-48788", "CVE-2022-48789", "CVE-2022-48790", "CVE-2022-48791", "CVE-2022-48798", "CVE-2022-48802", "CVE-2022-48805", "CVE-2022-48811", "CVE-2022-48823", "CVE-2022-48824", "CVE-2022-48827", "CVE-2022-48834", "CVE-2022-48835", "CVE-2022-48836", "CVE-2022-48837", "CVE-2022-48838", "CVE-2022-48839", "CVE-2022-48843", "CVE-2022-48851", "CVE-2022-48853", "CVE-2022-48856", "CVE-2022-48857", "CVE-2022-48858", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48901", "CVE-2022-48905", "CVE-2022-48912", "CVE-2022-48917", "CVE-2022-48919", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48928", "CVE-2022-48930", "CVE-2022-48933", "CVE-2022-48934", "CVE-2023-1582", "CVE-2023-2176", "CVE-2023-52854", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26800", "CVE-2024-40910", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41062", "CVE-2024-42077", "CVE-2024-42232", "CVE-2024-42271", "CVE-2024-43861", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-44947");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 20:03:31 +0000 (Mon, 19 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-18 04:00:27 +0000 (Wed, 18 Sep 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3249-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XGYYKHOW32CRWO2LEVWOZ4RXSNE5YX4N");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3249-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-44947: Initialize beyond-EOF page contents before setting up-to-date
      (bsc#1229454).

  * CVE-2022-48919: Fix double free race when mount fails in cifs_get_root()
      (bsc#1229657).

  * CVE-2023-52854: Fix refcnt handling in padata_free_shell() (bsc#1225584).

  * CVE-2024-43883: Do not drop references before new references are gained
      (bsc#1229707).

  * CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).

  * CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).

  * CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage.
      (bsc#1229503)

  * CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)

  * CVE-2022-48872: Fix use-after-free race condition for maps (bsc#1229510).

  * CVE-2022-48873: Do not remove map on creater_process and device_release
      (bsc#1229512).

  * CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)

  * CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop().
      (bsc#1228959)

  * CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).

  * CVE-2022-48686: Fixed UAF when detecting digest errors (bsc#1223948).

  * CVE-2024-41009: bpf: Fix overrunning reservations in ringbuf (bsc#1228020).

  * CVE-2022-48791: Fix use-after-free for aborted TMF sas_task (bsc#1228002)

  The following non-security bugs were fixed:

  * Bluetooth: L2CAP: Fix deadlock (git-fixes).

  * powerpc: Remove support for PowerPC 601 (Remove unused and malformed
      assembly causing build error).

  * sched/psi: use kernfs polling functions for PSI trigger polling (bsc#1209799
      bsc#1225109).

  * scsi: pm80xx: Fix TMF task completion race condition (bsc#1228002).

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

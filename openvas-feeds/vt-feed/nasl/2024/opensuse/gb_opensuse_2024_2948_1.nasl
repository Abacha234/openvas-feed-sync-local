# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856371");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-26558", "CVE-2021-0129", "CVE-2021-47126", "CVE-2021-47219", "CVE-2021-47291", "CVE-2021-47506", "CVE-2021-47520", "CVE-2021-47580", "CVE-2021-47598", "CVE-2021-47600", "CVE-2022-48792", "CVE-2022-48821", "CVE-2022-48822", "CVE-2023-52686", "CVE-2023-52885", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26800", "CVE-2024-36974", "CVE-2024-38559", "CVE-2024-39494", "CVE-2024-40937", "CVE-2024-40956", "CVE-2024-41011", "CVE-2024-41059", "CVE-2024-41069", "CVE-2024-41090", "CVE-2024-42145");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 19:17:25 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:05 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:2948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2948-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G7ZTYXQNURIOUE65IQFB7AMN43TVDK6K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:2948-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2020-26558: Fixed a flaw in the Bluetooth LE and BR/EDR secure pairing
      that could permit a nearby man-in-the-middle attacker to identify the
      Passkey used during pairing (bsc#1179610).

  * CVE-2021-0129: Improper access control in BlueZ may have allowed an
      authenticated user to potentially enable information disclosure via adjacent
      access (bsc#1186463).

  * CVE-2021-47126: ipv6: Fix KASAN: slab-out-of-bounds Read in
      fib6_nh_flush_exceptions (bsc#1221539).

  * CVE-2021-47219: scsi: scsi_debug: Fix out-of-bound read in
      resp_report_tgtpgs() (bsc#1222824).

  * CVE-2021-47291: ipv6: fix another slab-out-of-bounds in
      fib6_nh_flush_exceptions (bsc#1224918).

  * CVE-2021-47506: nfsd: fix use-after-free due to delegation race
      (bsc#1225404).

  * CVE-2021-47520: can: pch_can: pch_can_rx_normal: fix use after free
      (bsc#1225431).

  * CVE-2021-47580: scsi: scsi_debug: Fix type in min_t to avoid stack OOB
      (bsc#1226550).

  * CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init()
      (bsc#1226574).

  * CVE-2021-47600: dm btree remove: fix use after free in rebalance_children()
      (bsc#1226575).

  * CVE-2022-48792: scsi: pm8001: Fix use-after-free for aborted SSP/STP
      sas_task (bsc#1228013).

  * CVE-2022-48821: misc: fastrpc: avoid double fput() on failed usercopy
      (bsc#1227976).

  * CVE-2023-52686: Fix a null pointer in opal_event_init() (bsc#1065729).

  * CVE-2023-52885: SUNRPC: Fix UAF in svc_tcp_listen_data_ready()
      (bsc#1227750).

  * CVE-2024-26585: Fixed race between tx work scheduling and socket close
      (bsc#1220187).

  * CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP
      (bsc#1226519).

  * CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated
      (bsc#1226785).

  * CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name
      (bsc#1227716).

  * CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any()
      (bsc#1227836).

  * CVE-2024-40956: dmaengine: idxd: Fix possible Use-After-Free in
      irq_process_work_list (bsc#1227810).

  * CVE-2024-41011: drm/amdkfd: do not allow mapping the MMIO HDP page with
      large pages (bsc#1228114).

  * CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228561).

  * CVE-2024-41069: ASoC: topology: Fix route memory corruption (bsc#1228644).

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

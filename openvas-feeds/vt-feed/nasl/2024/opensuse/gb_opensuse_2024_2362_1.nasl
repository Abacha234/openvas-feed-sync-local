# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856308");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-3896", "CVE-2021-43389", "CVE-2021-4439", "CVE-2021-47247", "CVE-2021-47311", "CVE-2021-47328", "CVE-2021-47368", "CVE-2021-47372", "CVE-2021-47379", "CVE-2021-47571", "CVE-2021-47576", "CVE-2021-47583", "CVE-2021-47589", "CVE-2021-47595", "CVE-2021-47596", "CVE-2021-47600", "CVE-2021-47602", "CVE-2021-47609", "CVE-2021-47611", "CVE-2021-47612", "CVE-2021-47617", "CVE-2021-47618", "CVE-2021-47619", "CVE-2021-47620", "CVE-2022-0435", "CVE-2022-22942", "CVE-2022-2938", "CVE-2022-48711", "CVE-2022-48715", "CVE-2022-48717", "CVE-2022-48722", "CVE-2022-48724", "CVE-2022-48726", "CVE-2022-48728", "CVE-2022-48730", "CVE-2022-48732", "CVE-2022-48736", "CVE-2022-48737", "CVE-2022-48738", "CVE-2022-48746", "CVE-2022-48747", "CVE-2022-48748", "CVE-2022-48749", "CVE-2022-48752", "CVE-2022-48754", "CVE-2022-48756", "CVE-2022-48758", "CVE-2022-48759", "CVE-2022-48760", "CVE-2022-48767", "CVE-2022-48768", "CVE-2022-48771", "CVE-2023-24023", "CVE-2023-52707", "CVE-2023-52752", "CVE-2023-52881", "CVE-2024-26822", "CVE-2024-26923", "CVE-2024-35789", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35864", "CVE-2024-35878", "CVE-2024-35950", "CVE-2024-36894", "CVE-2024-36904", "CVE-2024-36940", "CVE-2024-36964", "CVE-2024-38541", "CVE-2024-38545", "CVE-2024-38559", "CVE-2024-38560");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:55 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2024-07-12 04:06:51 +0000 (Fri, 12 Jul 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:2362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2362-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VVQEZCVFAPVEXZCM2ZKZZJ7YTAM6QSZG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:2362-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47247: net/mlx5e: Fix use-after-free of encap entry in neigh update
      handler (bsc#1224865).

  * CVE-2021-47311: net: qcom/emac: fix UAF in emac_remove (bsc#1225010).

  * CVE-2021-47368: enetc: Fix illegal access when reading affinity_hint
      (bsc#1225161).

  * CVE-2021-47372: net: macb: fix use after free on rmmod (bsc#1225184).

  * CVE-2021-47379: blk-cgroup: fix UAF by grabbing blkcg lock before destroying
      blkg pd (bsc#1225203).

  * CVE-2021-47571: staging: rtl8192e: Fix use after free in
      _rtl92e_pci_disconnect() (bsc#1225518).

  * CVE-2022-48760: USB: core: Fix hang in usb_kill_urb by adding memory
      barriers (bsc#1226712).

  * CVE-2023-52707: sched/psi: Fix use-after-free in ep_remove_wait_queue()
      (bsc#1225109). polled (bsc#1202623).

  * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225487).

  * CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).

  * CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in
      __unix_gc() (bsc#1223384).

  * CVE-2024-35789: Check fast rx for non-4addr sta VLAN changes (bsc#1224749).

  * CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()
      (bsc#1224766).

  * CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()
      (bsc#1224764).

  * CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()
      (bsc#1224765).

  * CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex
      (bsc#1224703).

  * CVE-2024-36894: usb: gadget: f_fs: Fix race between aio_cancel() and AIO
      request complete (bsc#1225749).

  * CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique()
      (bsc#1225732).

  * CVE-2024-36940: pinctrl: core: delete incorrect free in pinctrl_enable()
      (bsc#1225840).

  * CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000
      (bsc#1225866).

  * CVE-2024-38545: RDMA/hns: Fix UAF for cq async event (bsc#1226595)

  * CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated
      (bsc#1226758).

  * CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated
      (bsc#1226786).

  The following non-security bugs were fixed:

  * NFS: avoid infinite loop in pnfs_update_layout (bsc#1219633 bsc#1226226).

  * ocfs2: adjust enabling place for la window (bsc#1219224).

  * ocfs2: fix sparse warnings  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856158");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-46955", "CVE-2021-47041", "CVE-2021-47074", "CVE-2021-47113", "CVE-2021-47131", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47194", "CVE-2021-47198", "CVE-2021-47201", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47212", "CVE-2021-47216", "CVE-2022-48631", "CVE-2022-48638", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48654", "CVE-2022-48672", "CVE-2022-48686", "CVE-2022-48687", "CVE-2022-48693", "CVE-2022-48695", "CVE-2022-48701", "CVE-2022-48702", "CVE-2023-2860", "CVE-2023-6270", "CVE-2024-0639", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-26610", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26744", "CVE-2024-26816", "CVE-2024-26840", "CVE-2024-26852", "CVE-2024-26862", "CVE-2024-26898", "CVE-2024-26903", "CVE-2024-26906", "CVE-2024-27043");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 19:31:26 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-24 01:08:29 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1642-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1642-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YW6MNPJCH32G5MKUKG23A4O4QAGRMGOF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1642-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-26840: Fixed a memory leak in cachefiles_add_cache() (bsc#1222976).

  * CVE-2021-47113: Abort btrfs rename_exchange if we fail to insert the second
      ref (bsc#1221543).

  * CVE-2021-47131: Fixed a use-after-free after the TLS device goes down and up
      (bsc#1221545).

  * CVE-2024-26852: Fixed net/ipv6 to avoid possible UAF in
      ip6_route_mpath_notify() (bsc#1223057).

  * CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when
      fragmenting IPv4 packets (bsc#1220513).

  * CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing
      (bsc#1223111).

  * CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock
      found in sctp_auto_asconf_init in net/sctp/socket.c (bsc#1218917).

  * CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places
      (bsc#1223824).

  * CVE-2022-48631: Fixed a bug in ext4, when parsing extents where eh_entries
      == 0 and eh_depth > 0 (bsc#1223475).

  * CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86
      and ARM md, raid, raid5 modules (bsc#1219169).

  * CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset
      skb->mac_header (bsc#1223513).

  * CVE-2024-26906: Disallowed vsyscall page read for copy_from_kernel_nofault()
      (bsc#1223202).

  * CVE-2024-26816: Fixed relocations in .notes section when building with
      CONFIG_XEN_PV=y by ignoring them (bsc#1222624).

  * CVE-2024-26610: Fixed memory corruption in wifi/iwlwifi (bsc#1221299).

  * CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).

  * CVE-2021-47041: Don't set sk_user_data without write_lock (bsc#1220755).

  * CVE-2021-47074: Fixed memory leak in nvme_loop_create_ctrl() (bsc#1220854).

  * CVE-2024-26744: Fixed null pointer dereference in srpt_service_guid
      parameter in rdma/srpt (bsc#1222449).

  The following non-security bugs were fixed:

  * dm rq: do not queue request to blk-mq during DM suspend (bsc#1221113).

  * dm: rearrange core declarations for extended use from dm-zone.c
      (bsc#1221113).

  * net/tls: Remove the context from the list in tls_device_down (bsc#1221545).

  * tls: Fix context leak on tls_device_down (bsc#1221545).

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

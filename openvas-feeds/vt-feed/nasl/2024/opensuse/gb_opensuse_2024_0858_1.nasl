# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856023");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2019-25162", "CVE-2021-46923", "CVE-2021-46924", "CVE-2021-46932", "CVE-2023-28746", "CVE-2023-5197", "CVE-2023-52340", "CVE-2023-52429", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52449", "CVE-2023-52451", "CVE-2023-52452", "CVE-2023-52456", "CVE-2023-52457", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52475", "CVE-2023-52478", "CVE-2023-6817", "CVE-2024-0607", "CVE-2024-1151", "CVE-2024-23849", "CVE-2024-23850", "CVE-2024-23851", "CVE-2024-25744", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26591", "CVE-2024-26593", "CVE-2024-26595", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26622");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 13:11:05 +0000 (Fri, 06 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:29:36 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:0858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0858-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D3NE26XLRHBTNYA7JOC5VRRIOJYSA72C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:0858-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2019-25162: Fixed a potential use after free (bsc#1220409).

  * CVE-2021-46923: Fixed reference leakage in fs/mount_setattr (bsc#1220457).

  * CVE-2021-46924: Fixed fix memory leak in device probe and remove
      (bsc#1220459)

  * CVE-2021-46932: Fixed missing work initialization before device registration
      (bsc#1220444)

  * CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).

  * CVE-2023-5197: Fixed se-after-free due to addition and removal of rules from
      chain bindings within the same transaction (bsc#1218216).

  * CVE-2023-52340: Fixed ICMPv6 Packet Too Big packets force a DoS of the
      Linux kernel by forcing 100% CPU (bsc#1219295).

  * CVE-2023-52429: Fixed potential DoS in dm_table_create in drivers/md/dm-
      table.c (bsc#1219827).

  * CVE-2023-52439: Fixed use-after-free in uio_open (bsc#1220140).

  * CVE-2023-52443: Fixed crash when parsed profile name is empty (bsc#1220240).

  * CVE-2023-52445: Fixed use after free on context disconnection (bsc#1220241).

  * CVE-2023-52447: Fixed map_fd_put_ptr() signature kABI workaround
      (bsc#1220251).

  * CVE-2023-52448: Fixed kernel NULL pointer dereference in gfs2_rgrp_dump
      (bsc#1220253).

  * CVE-2023-52449: Fixed gluebi NULL pointer dereference caused by ftl notifier
      (bsc#1220238).

  * CVE-2023-52451: Fixed access beyond end of drmem array (bsc#1220250).

  * CVE-2023-52452: Fixed Fix accesses to uninit stack slots (bsc#1220257).

  * CVE-2023-52456: Fixed tx statemachine deadlock (bsc#1220364).

  * CVE-2023-52457: Fixed skipped resource freeing if
      pm_runtime_resume_and_get() failed (bsc#1220350).

  * CVE-2023-52463: Fixed null pointer dereference in efivarfs (bsc#1220328).

  * CVE-2023-52464: Fixed possible out-of-bounds string access (bsc#1220330)

  * CVE-2023-52475: Fixed use-after-free in powermate_config_complete
      (bsc#1220649)

  * CVE-2023-52478: Fixed kernel crash on receiver USB disconnect (bsc#1220796)

  * CVE-2023-6817: Fixed use-after-free in nft_pipapo_walk (bsc#1218195).

  * CVE-2024-0607: Fixed 64-bit load issue in nft_byteorder_eval()
      (bsc#1218915).

  * CVE-2024-1151: Fixed unlimited number of recursions from action sets
      (bsc#1219835).

  * CVE-2024-23849: Fixed array-index-out-of-bounds in rds_cmsg_recv
      (bsc#1219127).

  * CVE-2024-23850: Fixed double free of anonymous device after snapshot
      creation failure (bsc#1219126).

  * C ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856555");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-47069", "CVE-2022-48911", "CVE-2022-48945", "CVE-2024-36971", "CVE-2024-41087", "CVE-2024-44946", "CVE-2024-45003", "CVE-2024-45021", "CVE-2024-46695", "CVE-2024-46774");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-08 18:00:03 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-10-11 04:00:24 +0000 (Fri, 11 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3585-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3585-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KQEELZFYMFWM7IH3U47G6HWPBOHSUNLH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3585-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47069: Fixed a crash due to relying on a stack reference past its
      expiry in ipc/mqueue, ipc/msg, ipc/sem (bsc#1220826).

  * CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance.
      (bsc#1229633).

  * CVE-2022-48945: media: vivid: fix compose size exceed boundary
      (bsc#1230398).

  * CVE-2024-41087: Fix double free on error (bsc#1228466).

  * CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket
      (bsc#1230015).

  * CVE-2024-45003: Don't evict inode under the inode lru traversing context
      (bsc#1230245).

  * CVE-2024-45021: memcg_write_event_control(): fix a user-triggerable oops
      (bsc#1230434).

  * CVE-2024-46695: selinux,smack: do not bypass permissions check in
      inode_setsecctx hook (bsc#1230519).

  * CVE-2024-36971: Fixed __dst_negative_advice() race (bsc#1226145).

  The following non-security bugs were fixed:

  * ext4: add check to prevent attempting to resize an fs with sparse_super2
      (bsc#1230326).

  * ext4: add reserved GDT blocks check (bsc#1230326).

  * ext4: consolidate checks for resize of bigalloc into ext4_resize_begin
      (bsc#1230326).

  * ext4: fix bug_on ext4_mb_use_inode_pa (bsc#1230326).

  * kabi: add __nf_queue_get_refs() for kabi compliance.

  * PKCS#7: Check codeSigning EKU of certificates in PKCS#7 (bsc#1226666).

  * Revert 'ext4: consolidate checks for resize of bigalloc into
      ext4_resize_begin' (bsc#1230326).

   Special Instructions and Notes:

  * Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

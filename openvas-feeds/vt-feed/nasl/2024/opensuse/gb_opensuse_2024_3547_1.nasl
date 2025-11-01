# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856540");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-48911", "CVE-2022-48923", "CVE-2022-48944", "CVE-2022-48945", "CVE-2024-41087", "CVE-2024-42301", "CVE-2024-44946", "CVE-2024-45021", "CVE-2024-46674", "CVE-2024-46774");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-13 16:51:45 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 04:00:32 +0000 (Wed, 09 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3547-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3547-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EMM6DS2PTSRTSYWBLCTLSJWQYCIASBUG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3547-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance.
      (bsc#1229633).

  * CVE-2022-48923: btrfs: prevent copying too big compressed lzo segment
      (bsc#1229662)

  * CVE-2024-41087: Fix double free on error (bsc#1228466).

  * CVE-2024-42301: Fix the array out-of-bounds risk (bsc#1229407).

  * CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket
      (bsc#1230015).

  * CVE-2024-45021: memcg_write_event_control(): fix a user-triggerable oops
      (bsc#1230434).

  * CVE-2024-46674: usb: dwc3: st: fix probed platform device ref count on probe
      error path (bsc#1230507).

  The following non-security bugs were fixed:

  * blk-mq: add helper for checking if one CPU is mapped to specified hctx
      (bsc#1223600).

  * blk-mq: do not schedule block kworker on isolated CPUs (bsc#1223600).

  * kabi: add __nf_queue_get_refs() for kabi compliance.

  * scsi: ibmvfc: Add max_sectors module parameter (bsc#1216223).

  * scsi: smartpqi: Expose SAS address for SATA drives (bsc#1223958).

  * SUNRPC: avoid soft lockup when transmitting UDP to reachable server
      (bsc#1225272 bsc#1231016).

   Special Instructions and Notes:

  * Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

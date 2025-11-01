# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856958");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-26924", "CVE-2024-27397", "CVE-2024-35839", "CVE-2024-36908", "CVE-2024-36915", "CVE-2024-39480", "CVE-2024-41042", "CVE-2024-44934", "CVE-2024-44996", "CVE-2024-47678", "CVE-2024-49854", "CVE-2024-49884", "CVE-2024-49915", "CVE-2024-50016", "CVE-2024-50018", "CVE-2024-50039", "CVE-2024-50047", "CVE-2024-50143", "CVE-2024-50154", "CVE-2024-50202", "CVE-2024-50203", "CVE-2024-50211", "CVE-2024-50228", "CVE-2024-50256", "CVE-2024-50262", "CVE-2024-50272", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-53050", "CVE-2024-53064", "CVE-2024-53090", "CVE-2024-53095", "CVE-2024-53099", "CVE-2024-53103", "CVE-2024-53105", "CVE-2024-53111", "CVE-2024-53113", "CVE-2024-53117", "CVE-2024-53118", "CVE-2024-53119", "CVE-2024-53120", "CVE-2024-53122", "CVE-2024-53125", "CVE-2024-53126", "CVE-2024-53127", "CVE-2024-53129", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53133", "CVE-2024-53134", "CVE-2024-53136", "CVE-2024-53141", "CVE-2024-53142", "CVE-2024-53144", "CVE-2024-53146", "CVE-2024-53148", "CVE-2024-53150", "CVE-2024-53151", "CVE-2024-53154", "CVE-2024-53155", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53158", "CVE-2024-53159", "CVE-2024-53160", "CVE-2024-53161", "CVE-2024-53162", "CVE-2024-53166", "CVE-2024-53169", "CVE-2024-53171", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53179", "CVE-2024-53180", "CVE-2024-53188", "CVE-2024-53190", "CVE-2024-53191", "CVE-2024-53200", "CVE-2024-53201", "CVE-2024-53202", "CVE-2024-53206", "CVE-2024-53207", "CVE-2024-53208", "CVE-2024-53209", "CVE-2024-53210", "CVE-2024-53213", "CVE-2024-53214", "CVE-2024-53215", "CVE-2024-53216", "CVE-2024-53217", "CVE-2024-53222", "CVE-2024-53224", "CVE-2024-53229", "CVE-2024-53234", "CVE-2024-53237", "CVE-2024-53240", "CVE-2024-53241", "CVE-2024-56536", "CVE-2024-56539", "CVE-2024-56549", "CVE-2024-56551", "CVE-2024-56562", "CVE-2024-56566", "CVE-2024-56567", "CVE-2024-56576", "CVE-2024-56582", "CVE-2024-56599", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56645", "CVE-2024-56667", "CVE-2024-56752", "CVE-2024-56754", "CVE-2024-56755", "CVE-2024-56756", "CVE-2024-8805");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-01-18 05:00:19 +0000 (Sat, 18 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2025:0154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0154-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VRH6XGVVLCH2IR7EYANVP3UCYWMJ3G4U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2025:0154-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-26924: scsi: lpfc: Release hbalock before calling
      lpfc_worker_wake_up() (bsc#1225820).

  * CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element
      timeout (bsc#1224095).

  * CVE-2024-35839: kABI fix for netfilter: bridge: replace physindev with
      physinif in nf_bridge_info (bsc#1224726).

  * CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies
      (bsc#1225758).

  * CVE-2024-41042: Prefer nft_chain_validate (bsc#1228526).

  * CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when
      removing port (bsc#1229809).

  * CVE-2024-44996: vsock: fix recursive ->recvmsg calls (bsc#1230205).

  * CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).

  * CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs
      (bsc#1232419).

  * CVE-2024-50039: kABI: Restore deleted
      EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).

  * CVE-2024-50202: nilfs2: propagate directory read errors from
      nilfs_find_entry() (bsc#1233324).

  * CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in
      nf_send_reset6() (bsc#1233200).

  * CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key()
      (bsc#1233239).

  * CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized
      delayed_work on cache_ctr error (bsc#1233467 bsc#1233469).

  * CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first
      resume (bsc#1233467).

  * CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when
      resizing (bsc#1233468).

  * CVE-2024-53050: drm/i915/hdcp: Add encoder check in hdcp2_get_capability
      (bsc#1233546).

  * CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558
      bsc#1234464).

  * CVE-2024-53090: afs: Fix lock recursion (bsc#1233637).

  * CVE-2024-53095: smb: client: Fix use-after-free of network namespace
      (bsc#1233642).

  * CVE-2024-53099: bpf: Check validity of link->type in bpf_link_show_fdinfo()
      (bsc#1233772).

  * CVE-2024-53105: mm: page_alloc: move mlocked flag clearance into
      free_pages_prepare() (bsc#1234069).

  * CVE-2024-53111: mm/mremap: fix address wraparound in move_page_tables()
      (bsc#1234086).

  * CVE-2024-53113: mm: fix NULL pointer dereference in alloc_pages_bulk_noprof
      (bsc#1234077).

  * CVE-2024-53117: virtio/vsock: Improve MSG_ZEROCOPY error handling
      (bs ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

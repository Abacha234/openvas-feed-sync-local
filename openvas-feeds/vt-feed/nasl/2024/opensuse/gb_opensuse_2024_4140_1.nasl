# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856777");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-47416", "CVE-2021-47589", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48947", "CVE-2022-48956", "CVE-2022-48960", "CVE-2022-48962", "CVE-2022-48967", "CVE-2022-48970", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48999", "CVE-2022-49003", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49023", "CVE-2022-49025", "CVE-2023-28327", "CVE-2023-46343", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-42145", "CVE-2024-44947", "CVE-2024-45016", "CVE-2024-45026", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46849", "CVE-2024-47668", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47706", "CVE-2024-47747", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49936", "CVE-2024-49969", "CVE-2024-49974", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49995", "CVE-2024-50047");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 22:16:21 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-12-03 05:03:18 +0000 (Tue, 03 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:4140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4140-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PQYSUTXFLVU7ZNPROUW7SREX4U4IKVZX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:4140-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47589: igbvf: fix double free in `igbvf_probe` (bsc#1226557).

  * CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).

  * CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx()
      (bsc#1231979).

  * CVE-2022-48962: net: hisilicon: Fix potential use-after-free in
      hisi_femac_rx() (bsc#1232286).

  * CVE-2022-48967: NFC: nci: Bounds check struct nfc_target arrays
      (bsc#1232304).

  * CVE-2022-48988: memcg: Fix possible use-after-free in
      memcg_write_event_control() (bsc#1232069).

  * CVE-2022-48991: khugepaged: retract_page_tables() remember to test exit
      (bsc#1232070 prerequisity).

  * CVE-2022-49003: nvme: fix SRCU protection of nvme_ns_head list
      (bsc#1232136).

  * CVE-2022-49014: net: tun: Fix use-after-free in tun_detach() (bsc#1231890).

  * CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).

  * CVE-2022-49023: wifi: cfg80211: fix buffer overflow in elem comparison
      (bsc#1231961).

  * CVE-2022-49025: net/mlx5e: Fix use-after-free when reverting termination
      table (bsc#1231960).

  * CVE-2024-45016: netem: fix return value if duplicate enqueue fails
      (bsc#1230429).

  * CVE-2024-45026: s390/dasd: fix error recovery leading to data corruption on
      ESE devices (bsc#1230454).

  * CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links
      (bsc#1231191).

  * CVE-2024-46814: drm/amd/display: Check msg_id before processing transaction
      (bsc#1231193).

  * CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums
      greater than max_links (bsc#1231197).

  * CVE-2024-46817: drm/amd/display: Stop amdgpu_dm initialize when stream nums
      greater than 6 (bsc#1231200).

  * CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index
      (bsc#1231203).

  * CVE-2024-46849: ASoC: meson: axg-card: fix 'use-after-free' (bsc#1231073).

  * CVE-2024-47668: lib/generic-radix-tree.c: Fix rare race in
      __genradix_ptr_alloc() (bsc#1231502).

  * CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case
      (bsc#1231673).

  * CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us()
      (bsc#1231987).

  * CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain
      (bsc#1231942).

  * CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver
      Due to Race Co ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

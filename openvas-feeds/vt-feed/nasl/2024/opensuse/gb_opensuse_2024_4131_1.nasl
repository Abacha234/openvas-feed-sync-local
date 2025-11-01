# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856769");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-47416", "CVE-2021-47534", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48879", "CVE-2022-48946", "CVE-2022-48947", "CVE-2022-48948", "CVE-2022-48949", "CVE-2022-48951", "CVE-2022-48953", "CVE-2022-48954", "CVE-2022-48955", "CVE-2022-48956", "CVE-2022-48959", "CVE-2022-48960", "CVE-2022-48961", "CVE-2022-48962", "CVE-2022-48967", "CVE-2022-48968", "CVE-2022-48969", "CVE-2022-48970", "CVE-2022-48971", "CVE-2022-48972", "CVE-2022-48973", "CVE-2022-48975", "CVE-2022-48977", "CVE-2022-48978", "CVE-2022-48981", "CVE-2022-48985", "CVE-2022-48987", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48992", "CVE-2022-48994", "CVE-2022-48995", "CVE-2022-48997", "CVE-2022-48999", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49003", "CVE-2022-49005", "CVE-2022-49006", "CVE-2022-49007", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49012", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49016", "CVE-2022-49019", "CVE-2022-49021", "CVE-2022-49022", "CVE-2022-49023", "CVE-2022-49024", "CVE-2022-49025", "CVE-2022-49026", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49029", "CVE-2022-49031", "CVE-2022-49032", "CVE-2023-2166", "CVE-2023-28327", "CVE-2023-52766", "CVE-2023-52800", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-42145", "CVE-2024-43854", "CVE-2024-44947", "CVE-2024-45013", "CVE-2024-45016", "CVE-2024-45026", "CVE-2024-46716", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46849", "CVE-2024-47668", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47706", "CVE-2024-47747", "CVE-2024-47748", "CVE-2024-49860", "CVE-2024-49867", "CVE-2024-49925", "CVE-2024-49930", "CVE-2024-49936", "CVE-2024-49945", "CVE-2024-49960", "CVE-2024-49969", "CVE-2024-49974", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49995", "CVE-2024-50047", "CVE-2024-50208");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 22:16:21 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-12-03 05:01:33 +0000 (Tue, 03 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:4131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4131-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YRR2ET2Y3HE3F7G6O5WO56QMZS54PCA6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:4131-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-43854: Initialize integrity buffer to zero before writing it to
      media (bsc#1229345)

  * CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core
      (bsc#1232224)

  * CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the
      associated structure (bsc#1232165).

  * CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages
      (bsc#1233117).

  * CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).

  * CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).

  * CVE-2022-48959: net: dsa: sja1105: fix memory leak in
      sja1105_setup_devlink_regions() (bsc#1231976).

  * CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx()
      (bsc#1231979).

  * CVE-2022-48962: net: hisilicon: Fix potential use-after-free in
      hisi_femac_rx() (bsc#1232286).

  * CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow
      anon_vma (bsc#1232070).

  * CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).

  * CVE-2024-45013: nvme: move stopping keep-alive into nvme_uninit_ctrl()
      (bsc#1230442).

  * CVE-2024-45016: netem: fix return value if duplicate enqueue fails
      (bsc#1230429).

  * CVE-2024-45026: s390/dasd: fix error recovery leading to data corruption on
      ESE devices (bsc#1230454).

  * CVE-2024-46716: dmaengine: altera-msgdma: properly free descriptor in
      msgdma_free_descriptor (bsc#1230715).

  * CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links
      (bsc#1231191).

  * CVE-2024-46814: drm/amd/display: Check msg_id before processing transaction
      (bsc#1231193).

  * CVE-2024-46815: drm/amd/display: Check num_valid_sets before accessing
      reader_wm_sets (bsc#1231195).

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

  * CVE-2024-47 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

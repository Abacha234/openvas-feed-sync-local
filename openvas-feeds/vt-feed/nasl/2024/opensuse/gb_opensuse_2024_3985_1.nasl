# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856720");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-47416", "CVE-2021-47534", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48879", "CVE-2022-48946", "CVE-2022-48947", "CVE-2022-48948", "CVE-2022-48949", "CVE-2022-48951", "CVE-2022-48953", "CVE-2022-48954", "CVE-2022-48955", "CVE-2022-48956", "CVE-2022-48957", "CVE-2022-48958", "CVE-2022-48959", "CVE-2022-48960", "CVE-2022-48961", "CVE-2022-48962", "CVE-2022-48966", "CVE-2022-48967", "CVE-2022-48968", "CVE-2022-48969", "CVE-2022-48970", "CVE-2022-48971", "CVE-2022-48972", "CVE-2022-48973", "CVE-2022-48975", "CVE-2022-48977", "CVE-2022-48978", "CVE-2022-48980", "CVE-2022-48981", "CVE-2022-48985", "CVE-2022-48987", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48992", "CVE-2022-48994", "CVE-2022-48995", "CVE-2022-48997", "CVE-2022-48999", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49003", "CVE-2022-49005", "CVE-2022-49006", "CVE-2022-49007", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49012", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49016", "CVE-2022-49017", "CVE-2022-49019", "CVE-2022-49020", "CVE-2022-49021", "CVE-2022-49022", "CVE-2022-49023", "CVE-2022-49024", "CVE-2022-49025", "CVE-2022-49026", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49029", "CVE-2022-49031", "CVE-2022-49032", "CVE-2023-2166", "CVE-2023-28327", "CVE-2023-52766", "CVE-2023-52800", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-36244", "CVE-2024-36957", "CVE-2024-39476", "CVE-2024-40965", "CVE-2024-42145", "CVE-2024-42226", "CVE-2024-42253", "CVE-2024-44931", "CVE-2024-44947", "CVE-2024-44958", "CVE-2024-45016", "CVE-2024-45025", "CVE-2024-46678", "CVE-2024-46716", "CVE-2024-46719", "CVE-2024-46754", "CVE-2024-46770", "CVE-2024-46775", "CVE-2024-46777", "CVE-2024-46809", "CVE-2024-46811", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46826", "CVE-2024-46828", "CVE-2024-46834", "CVE-2024-46840", "CVE-2024-46841", "CVE-2024-46848", "CVE-2024-46849", "CVE-2024-46854", "CVE-2024-46855", "CVE-2024-46857", "CVE-2024-47660", "CVE-2024-47661", "CVE-2024-47664", "CVE-2024-47668", "CVE-2024-47672", "CVE-2024-47673", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47692", "CVE-2024-47704", "CVE-2024-47705", "CVE-2024-47706", "CVE-2024-47707", "CVE-2024-47710", "CVE-2024-47720", "CVE-2024-47727", "CVE-2024-47730", "CVE-2024-47738", "CVE-2024-47739", "CVE-2024-47745", "CVE-2024-47747", "CVE-2024-47748", "CVE-2024-49858", "CVE-2024-49860", "CVE-2024-49866", "CVE-2024-49867", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49886", "CVE-2024-49890", "CVE-2024-49892", "CVE-2024-49894", "CVE-2024-49895", "CVE-2024-49896", "CVE-2024-49897", "CVE-2024-49899", "CVE-2024-49901", "CVE-2024-49906", "CVE-2024-49908", "CVE-2024-49909", "CVE-2024-49911", "CVE-2024-49912", "CVE-2024-49913", "CVE-2024-49914", "CVE-2024-49917", "CVE-2024-49918", "CVE-2024-49919", "CVE-2024-49920", "CVE-2024-49922", "CVE-2024-49923", "CVE-2024-49929", "CVE-2024-49930", "CVE-2024-49933", "CVE-2024-49936", "CVE-2024-49939", "CVE-2024-49946", "CVE-2024-49949", "CVE-2024-49954", "CVE-2024-49955", "CVE-2024-49958", "CVE-2024-49959", "CVE-2024-49960", "CVE-2024-49962", "CVE-2024-49967", "CVE-2024-49969", "CVE-2024-49973", "CVE-2024-49974", "CVE-2024-49975", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49993", "CVE-2024-49995", "CVE-2024-49996", "CVE-2024-50000", "CVE-2024-50001", "CVE-2024-50002", "CVE-2024-50006", "CVE-2024-50014", "CVE-2024-50019", "CVE-2024-50024", "CVE-2024-50028", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50041", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50047", "CVE-2024-50048", "CVE-2024-50049", "CVE-2024-50055", "CVE-2024-50058", "CVE-2024-50059", "CVE-2024-50061", "CVE-2024-50063", "CVE-2024-50081");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-14 05:00:27 +0000 (Thu, 14 Nov 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3985-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3985-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KB6DG7QR5KXDQRV57H4IY2TB2LW42K4S");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3985-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).

  * CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).

  * CVE-2022-48957: dpaa2-switch: Fix memory leak in
      dpaa2_switch_acl_entry_add() and dpaa2_switch_acl_entry_remove()
      (bsc#1231973).

  * CVE-2022-48958: ethernet: aeroflex: fix potential skb leak in
      greth_init_rings() (bsc#1231889).

  * CVE-2022-48959: net: dsa: sja1105: fix memory leak in
      sja1105_setup_devlink_regions() (bsc#1231976).

  * CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx()
      (bsc#1231979).

  * CVE-2022-48962: net: hisilicon: Fix potential use-after-free in
      hisi_femac_rx() (bsc#1232286).

  * CVE-2022-48966: net: mvneta: Fix an out of bounds check (bsc#1232191).

  * CVE-2022-48980: net: dsa: sja1105: avoid out of bounds access in
      sja1105_init_l2_policing() (bsc#1232233).

  * CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow
      anon_vma (bsc#1232070).

  * CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).

  * CVE-2022-49017: tipc: re-fetch skb cb after tipc_msg_validate (bsc#1232004).

  * CVE-2022-49020: net/9p: Fix a potential socket leak in p9_socket_open
      (bsc#1232175).

  * CVE-2024-36244: net/sched: taprio: extend minimum interval restriction to
      entire cycle too (bsc#1226797).

  * CVE-2024-36957: octeontx2-af: avoid off-by-one read from userspace
      (bsc#1225762).

  * CVE-2024-39476: md/raid5: fix deadlock that raid5d() wait for itself to
      clear MD_SB_CHANGE_PENDING (bsc#1227437).

  * CVE-2024-40965: i2c: lpi2c: Avoid calling clk_get_rate during transfer
      (bsc#1227885).

  * CVE-2024-42226: Prevent potential failure in handle_tx_event() for Transfer
      events without TRB (bsc#1228709).

  * CVE-2024-42253: gpio: pca953x: fix pca953x_irq_bus_sync_unlock race
      (bsc#1229005).

  * CVE-2024-44931: gpio: prevent potential speculation leaks in
      gpio_device_get_desc() (bsc#1229837).

  * CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc
      (bsc#1230179).

  * CVE-2024-45016: netem: fix return value if duplicate enqueue fails
      (bsc#1230429).

  * CVE-2024-45025: fix bitmap corruption on close_range() with
      CLOSE_RANGE_UNSHARE (bsc#1230456).

  * CVE-2024-46678: bonding: change ipsec_lock from spin lock to mutex
      (bsc#1230550).

  * CVE-2024-46716: dmaengine:  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

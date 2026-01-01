# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21147.1");
  script_cve_id("CVE-2025-21816", "CVE-2025-38653", "CVE-2025-38718", "CVE-2025-39676", "CVE-2025-39702", "CVE-2025-39756", "CVE-2025-39779", "CVE-2025-39797", "CVE-2025-39812", "CVE-2025-39866", "CVE-2025-39876", "CVE-2025-39881", "CVE-2025-39895", "CVE-2025-39903", "CVE-2025-39911", "CVE-2025-39947", "CVE-2025-39948", "CVE-2025-39949", "CVE-2025-39950", "CVE-2025-39955", "CVE-2025-39956", "CVE-2025-39963", "CVE-2025-39965", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39978", "CVE-2025-39979", "CVE-2025-39981", "CVE-2025-39982", "CVE-2025-39984", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39991", "CVE-2025-39992", "CVE-2025-39993", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39997", "CVE-2025-40000", "CVE-2025-40005", "CVE-2025-40009", "CVE-2025-40011", "CVE-2025-40012", "CVE-2025-40013", "CVE-2025-40016", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40020", "CVE-2025-40029", "CVE-2025-40032", "CVE-2025-40035", "CVE-2025-40036", "CVE-2025-40037", "CVE-2025-40040", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40051", "CVE-2025-40052", "CVE-2025-40056", "CVE-2025-40058", "CVE-2025-40060", "CVE-2025-40061", "CVE-2025-40062", "CVE-2025-40071", "CVE-2025-40078", "CVE-2025-40080", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40091", "CVE-2025-40096", "CVE-2025-40100", "CVE-2025-40104", "CVE-2025-40364");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-17 14:06:37 +0000 (Mon, 17 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21147-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521147-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252939");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023511.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:21147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 16.0 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2025-21816: hrtimers: Force migrate away hrtimers queued after (bsc#1238472).
- CVE-2025-38653: proc: use the same treatment to check proc_lseek as ones for proc_read_iter et.al (bsc#1248630).
- CVE-2025-38718: sctp: linearize cloned gso packets in sctp_rcv (bsc#1249161).
- CVE-2025-39676: scsi: qla4xxx: Prevent a potential error pointer dereference (bsc#1249302).
- CVE-2025-39702: ipv6: sr: Fix MAC comparison to be constant-time (bsc#1249317).
- CVE-2025-39756: fs: Prevent file descriptor table allocations exceeding INT_MAX (bsc#1249512).
- CVE-2025-39779: btrfs: subpage: keep TOWRITE tag until folio is cleaned (bsc#1249495).
- CVE-2025-39812: sctp: initialize more fields in sctp_v6_from_sk() (bsc#1250202).
- CVE-2025-39866: fs: writeback: fix use-after-free in __mark_inode_dirty() (bsc#1250455).
- CVE-2025-39876: net: fec: Fix possible NPD in fec_enet_phy_reset_after_clk_enable() (bsc#1250400).
- CVE-2025-39881: kernfs: Fix UAF in polling when open file is released (bsc#1250379).
- CVE-2025-39895: sched: Fix sched_numa_find_nth_cpu() if mask offline (bsc#1250721).
- CVE-2025-39903: of_numa: fix uninitialized memory nodes causing kernel panic (bsc#1250749).
- CVE-2025-39911: i40e: fix IRQ freeing in i40e_vsi_request_irq_msix error path (bsc#1250704).
- CVE-2025-39947: net/mlx5e: Harden uplink netdev access against device unbind (bsc#1251232).
- CVE-2025-39948: ice: fix Rx page leak on multi-buffer frames (bsc#1251233).
- CVE-2025-39949: qed: Don't collect too many protection override GRC elements (bsc#1251177).
- CVE-2025-39950: net/tcp: Fix a NULL pointer dereference when using TCP-AO with TCP_REPAIR (bsc#1251176).
- CVE-2025-39955: tcp: Clear tcp_sk(sk)->fastopen_rsk in tcp_disconnect() (bsc#1251804).
- CVE-2025-39956: igc: don't fail igc_probe() on LED setup error (bsc#1251809).
- CVE-2025-39963: io_uring: fix incorrect io_kiocb reference in io_link_skb (bsc#1251819).
- CVE-2025-39968: i40e: add max boundary check for VF filters (bsc#1252047).
- CVE-2025-39969: i40e: fix validation of VF state in get resources (bsc#1252044).
- CVE-2025-39970: i40e: fix input validation logic for action_meta (bsc#1252051).
- CVE-2025-39971: i40e: fix idx validation in config queues msg (bsc#1252052).
- CVE-2025-39972: i40e: fix idx validation in i40e_validate_queue_map (bsc#1252039).
- CVE-2025-39973: i40e: add validation for ring_len param (bsc#1252035).
- CVE-2025-39978: octeontx2-pf: Fix potential use after free in otx2_tc_add_flow() (bsc#1252069).
- CVE-2025-39979: net/mlx5: fs, add API for sharing HWS action by refcount (bsc#1252067).
- CVE-2025-39984: net: tun: Update napi->skb after XDP process (bsc#1252081).
- CVE-2025-39992: mm: swap: check for stable address space before operating on the VMA (bsc#1252076).
- CVE-2025-40000: wifi: rtw89: fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.12.0~160000.6.1.160000.2.4", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.12.0~160000.7.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

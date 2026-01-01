# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4422.1");
  script_cve_id("CVE-2022-50253", "CVE-2023-53676", "CVE-2025-21710", "CVE-2025-37916", "CVE-2025-38359", "CVE-2025-38361", "CVE-2025-39788", "CVE-2025-39805", "CVE-2025-39819", "CVE-2025-39859", "CVE-2025-39944", "CVE-2025-39980", "CVE-2025-40001", "CVE-2025-40021", "CVE-2025-40027", "CVE-2025-40030", "CVE-2025-40038", "CVE-2025-40040", "CVE-2025-40048", "CVE-2025-40055", "CVE-2025-40059", "CVE-2025-40064", "CVE-2025-40070", "CVE-2025-40074", "CVE-2025-40075", "CVE-2025-40083", "CVE-2025-40098", "CVE-2025-40105", "CVE-2025-40107", "CVE-2025-40109", "CVE-2025-40110", "CVE-2025-40111", "CVE-2025-40115", "CVE-2025-40116", "CVE-2025-40118", "CVE-2025-40120", "CVE-2025-40121", "CVE-2025-40127", "CVE-2025-40129", "CVE-2025-40139", "CVE-2025-40140", "CVE-2025-40141", "CVE-2025-40149", "CVE-2025-40154", "CVE-2025-40156", "CVE-2025-40157", "CVE-2025-40159", "CVE-2025-40164", "CVE-2025-40168", "CVE-2025-40169", "CVE-2025-40171", "CVE-2025-40172", "CVE-2025-40173", "CVE-2025-40176", "CVE-2025-40180", "CVE-2025-40183", "CVE-2025-40186", "CVE-2025-40188", "CVE-2025-40194", "CVE-2025-40198", "CVE-2025-40200", "CVE-2025-40204", "CVE-2025-40205", "CVE-2025-40206", "CVE-2025-40207");
  script_tag(name:"creation_date", value:"2025-12-19 04:23:19 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-12 21:21:21 +0000 (Fri, 12 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4422-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254422-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253779");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023573.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:4422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50253: bpf: make sure skb->len != 0 when redirecting to a tunneling device (bsc#1249912).
- CVE-2023-53676: scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show() (bsc#1251786).
- CVE-2025-21710: tcp: correct handling of extreme memory squeeze (bsc#1237888).
- CVE-2025-37916: pds_core: remove write-after-free of client_id (bsc#1243474).
- CVE-2025-38359: s390/mm: Fix in_atomic() handling in do_secure_storage_access() (bsc#1247076).
- CVE-2025-38361: drm/amd/display: Check dce_hwseq before dereferencing it (bsc#1247079).
- CVE-2025-39788: scsi: ufs: exynos: Fix programming of HCI_UTRL_NEXUS_TYPE (bsc#1249547).
- CVE-2025-39805: net: macb: fix unregister_netdev call order in macb_remove() (bsc#1249982).
- CVE-2025-39819: fs/smb: Fix inconsistent refcnt update (bsc#1250176).
- CVE-2025-39859: ptp: ocp: fix use-after-free bugs causing by ptp_ocp_watchdog (bsc#1250252).
- CVE-2025-39944: octeontx2-pf: Fix use-after-free bugs in otx2_sync_tstamp() (bsc#1251120).
- CVE-2025-39980: nexthop: Forbid FDB status change while nexthop is in a group (bsc#1252063).
- CVE-2025-40001: scsi: mvsas: Fix use-after-free bugs in mvs_work_queue (bsc#1252303).
- CVE-2025-40021: tracing: dynevent: Add a missing lockdown check on dynevent (bsc#1252681).
- CVE-2025-40027: net/9p: fix double req put in p9_fd_cancelled (bsc#1252763).
- CVE-2025-40030: pinctrl: check the return value of pinmux_ops::get_function_name() (bsc#1252773).
- CVE-2025-40038: KVM: SVM: Skip fastpath emulation on VM-Exit if next RIP isn't valid (bsc#1252817).
- CVE-2025-40040: mm/ksm: fix flag-dropping behavior in ksm_madvise (bsc#1252780).
- CVE-2025-40048: uio_hv_generic: Let userspace take care of interrupt mask (bsc#1252862).
- CVE-2025-40055: ocfs2: fix double free in user_cluster_connect() (bsc#1252821).
- CVE-2025-40059: coresight: Fix incorrect handling for return value of devm_kzalloc (bsc#1252809).
- CVE-2025-40064: smc: Fix use-after-free in __pnet_find_base_ndev() (bsc#1252845).
- CVE-2025-40070: pps: fix warning in pps_register_cdev when register device fail (bsc#1252836).
- CVE-2025-40074: ipv4: start using dst_dev_rcu() (bsc#1252794).
- CVE-2025-40075: tcp_metrics: use dst_dev_net_rcu() (bsc#1252795).
- CVE-2025-40083: net/sched: sch_qfq: Fix null-deref in agg_dequeue (bsc#1252912).
- CVE-2025-40098: ALSA: hda: cs35l41: Fix NULL pointer dereference in cs35l41_get_acpi_mute_state() (bsc#1252917).
- CVE-2025-40105: vfs: Don't leak disconnected dentries on umount (bsc#1252928).
- CVE-2025-40139: smc: Use __sk_dst_get() and dst_dev_rcu() in in smc_clc_prfx_set() (bsc#1253409).
- CVE-2025-40149: tls: Use __sk_dst_get() and dst_dev_rcu() in get_netdev_for_sock() (bsc#1253355).
- CVE-2025-40159: xsk: Harden userspace-supplied xdp_desc validation (bsc#1253403).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.81.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.81.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.81.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.81.3.150600.12.36.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.81.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.81.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.81.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.81.3", rls:"SLES15.0SP6"))) {
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

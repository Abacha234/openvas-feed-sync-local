# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4515.1");
  script_cve_id("CVE-2022-50364", "CVE-2022-50368", "CVE-2022-50494", "CVE-2022-50545", "CVE-2022-50551", "CVE-2022-50569", "CVE-2022-50578", "CVE-2023-53229", "CVE-2023-53369", "CVE-2023-53431", "CVE-2023-53542", "CVE-2023-53597", "CVE-2023-53641", "CVE-2023-53676", "CVE-2025-38436", "CVE-2025-39819", "CVE-2025-39967", "CVE-2025-40001", "CVE-2025-40027", "CVE-2025-40030", "CVE-2025-40040", "CVE-2025-40048", "CVE-2025-40055", "CVE-2025-40070", "CVE-2025-40083", "CVE-2025-40173", "CVE-2025-40186", "CVE-2025-40204", "CVE-2025-40205");
  script_tag(name:"creation_date", value:"2025-12-26 04:24:39 +0000 (Fri, 26 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-12 16:35:51 +0000 (Fri, 12 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4515-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4515-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254515-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253456");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023647.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:4515-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50364: i2c: mux: reg: check return value after calling platform_get_resource() (bsc#1250083).
- CVE-2022-50368: drm/msm/dsi: fix memory corruption with too many bridges (bsc#1250009).
- CVE-2022-50494: thermal: intel_powerclamp: Use get_cpu() instead of smp_processor_id() to avoid crash (bsc#1251173).
- CVE-2022-50545: r6040: Fix kmemleak in probe and remove (bsc#1251285).
- CVE-2022-50551: wifi: brcmfmac: Fix potential shift-out-of-bounds in brcmf_fw_alloc_request() (bsc#1251322).
- CVE-2022-50569: xfrm: Update ipcomp_scratches with NULL when freed (bsc#1252640).
- CVE-2022-50578: class: fix possible memory leak in __class_register() (bsc#1252519).
- CVE-2023-53229: wifi: mac80211: fix invalid drv_sta_pre_rcu_remove calls for non-uploaded sta (bsc#1249650).
- CVE-2023-53369: net: dcb: choose correct policy to parse DCB_ATTR_BCN (bsc#1250206).
- CVE-2023-53431: scsi: ses: Don't attach if enclosure has no components (bsc#1250374).
- CVE-2023-53542: ARM: dts: exynos: Use Exynos5420 compatible for the MIPI video phy (bsc#1251154).
- CVE-2023-53597: cifs: fix mid leak during reconnection after timeout threshold (bsc#1251159).
- CVE-2023-53641: wifi: ath9k: hif_usb: fix memory leak of remain_skbs (bsc#1251728).
- CVE-2023-53676: scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show() (bsc#1251786).
- CVE-2025-38436: drm/scheduler: signal scheduled fence when kill job (bsc#1247227).
- CVE-2025-39819: fs/smb: Fix inconsistent refcnt update (bsc#1250176).
- CVE-2025-39967: fbcon: fix integer overflow in fbcon_do_set_font (bsc#1252033).
- CVE-2025-40001: scsi: mvsas: Fix use-after-free bugs in mvs_work_queue (bsc#1252303).
- CVE-2025-40027: net/9p: fix double req put in p9_fd_cancelled (bsc#1252763).
- CVE-2025-40030: pinctrl: check the return value of pinmux_ops::get_function_name() (bsc#1252773).
- CVE-2025-40040: mm/ksm: fix flag-dropping behavior in ksm_madvise (bsc#1252780).
- CVE-2025-40048: uio_hv_generic: Let userspace take care of interrupt mask (bsc#1252862).
- CVE-2025-40055: ocfs2: fix double free in user_cluster_connect() (bsc#1252821).
- CVE-2025-40070: pps: fix warning in pps_register_cdev when register device fail (bsc#1252836).
- CVE-2025-40083: net/sched: sch_qfq: Fix null-deref in agg_dequeue (bsc#1252912).
- CVE-2025-40173: net/ip6_tunnel: Prevent perpetual tunnel growth (bsc#1253421).
- CVE-2025-40204: sctp: Fix MAC comparison to be constant-time (bsc#1253436).
- CVE-2025-40205: btrfs: avoid potential out-of-bounds in btrfs_encode_fh() (bsc#1253456).

The following non-security bugs were fixed:

- KVM: x86: Give a hint when Win2016 might fail to boot due to XSAVES erratum (git-fixes).
- PCI: aardvark: Fix checking for MEM resource type (git-fixes).
- cifs: Check the lease context if we actually got a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.283.1", rls:"SLES12.0SP5"))) {
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

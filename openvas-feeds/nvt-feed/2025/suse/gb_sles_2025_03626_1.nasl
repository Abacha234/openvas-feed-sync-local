# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03626.1");
  script_cve_id("CVE-2021-4460", "CVE-2022-2602", "CVE-2022-2978", "CVE-2022-36280", "CVE-2022-43945", "CVE-2022-49980", "CVE-2022-50233", "CVE-2022-50234", "CVE-2022-50235", "CVE-2022-50248", "CVE-2022-50249", "CVE-2022-50252", "CVE-2022-50257", "CVE-2022-50258", "CVE-2022-50260", "CVE-2022-50271", "CVE-2022-50272", "CVE-2022-50299", "CVE-2022-50309", "CVE-2022-50312", "CVE-2022-50317", "CVE-2022-50330", "CVE-2022-50344", "CVE-2022-50355", "CVE-2022-50359", "CVE-2022-50367", "CVE-2022-50368", "CVE-2022-50375", "CVE-2022-50381", "CVE-2022-50385", "CVE-2022-50386", "CVE-2022-50401", "CVE-2022-50408", "CVE-2022-50409", "CVE-2022-50410", "CVE-2022-50412", "CVE-2022-50414", "CVE-2022-50419", "CVE-2022-50422", "CVE-2022-50427", "CVE-2022-50431", "CVE-2022-50435", "CVE-2022-50437", "CVE-2022-50440", "CVE-2022-50444", "CVE-2022-50454", "CVE-2022-50458", "CVE-2022-50459", "CVE-2022-50467", "CVE-2023-1380", "CVE-2023-28328", "CVE-2023-31248", "CVE-2023-3772", "CVE-2023-39197", "CVE-2023-42753", "CVE-2023-53147", "CVE-2023-53178", "CVE-2023-53179", "CVE-2023-53213", "CVE-2023-53220", "CVE-2023-53265", "CVE-2023-53273", "CVE-2023-53304", "CVE-2023-53321", "CVE-2023-53333", "CVE-2023-53438", "CVE-2023-53464", "CVE-2023-53492", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-53093", "CVE-2024-58240", "CVE-2025-21969", "CVE-2025-38011", "CVE-2025-38184", "CVE-2025-38216", "CVE-2025-38488", "CVE-2025-38553", "CVE-2025-38572", "CVE-2025-38664", "CVE-2025-38685", "CVE-2025-38713", "CVE-2025-39751", "CVE-2025-39823");
  script_tag(name:"creation_date", value:"2025-10-20 04:15:18 +0000 (Mon, 20 Oct 2025)");
  script_version("2025-10-21T05:39:32+0000");
  script_tag(name:"last_modification", value:"2025-10-21 05:39:32 +0000 (Tue, 21 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-14 12:36:32 +0000 (Mon, 14 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03626-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03626-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503626-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250891");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042188.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:03626-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49980: USB: gadget: fix use-after-free read in usb_udc_uevent() (bsc#1245110).
- CVE-2022-50233: Bluetooth: eir: Fix using strlen with hdev->{dev_name,short_name} (bsc#1246968).
- CVE-2022-50248: wifi: iwlwifi: mvm: fix double free on tx path (bsc#1249840).
- CVE-2022-50252: igb: Do not free q_vector unless new one was allocated (bsc#1249846).
- CVE-2022-50258: wifi: brcmfmac: Fix potential stack-out-of-bounds in brcmf_c_preinit_dcmds() (bsc#1249947).
- CVE-2022-50381: md: fix a crash in mempool_free (bsc#1250257).
- CVE-2022-50386: Bluetooth: L2CAP: Fix user-after-free (bsc#1250301).
- CVE-2022-50401: nfsd: under NFSv4.1, fix double svc_xprt_put on rpc_create failure (bsc#1250140).
- CVE-2022-50408: wifi: brcmfmac: fix use-after-free bug in brcmf_netdev_start_xmit() (bsc#1250391).
- CVE-2022-50409: net: If sock is dead do not access sock's sk_wq in sk_stream_wait_memory (bsc#1250392).
- CVE-2022-50412: drm: bridge: adv7511: unregister cec i2c device after cec adapter (bsc#1250189).
- CVE-2023-53178: mm: fix zswap writeback race condition (bsc#1249827).
- CVE-2023-53220: media: az6007: Fix null-ptr-deref in az6007_i2c_xfer() (bsc#1250337).
- CVE-2023-53321: wifi: mac80211_hwsim: drop short frames (bsc#1250313).
- CVE-2023-53438: x86/MCE: Always save CS register on AMD Zen IF Poison errors (bsc#1250180).
- CVE-2024-53093: nvme-multipath: defer partition scanning (bsc#1233640).
- CVE-2025-21969: kABI workaround for l2cap_conn changes (bsc#1240784).
- CVE-2025-38011: drm/amdgpu: csa unmap use uninterruptible lock (bsc#1244729).
- CVE-2025-38184: tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer (bsc#1245956).
- CVE-2025-38216: iommu/vt-d: Restore context entry setup order for aliased devices (bsc#1245963).
- CVE-2025-38488: smb: client: fix use-after-free in crypt_message when using async crypto (bsc#1247239).
- CVE-2025-38553: net/sched: Restrict conditions for adding duplicating netems to qdisc tree (bsc#1248255).
- CVE-2025-38572: ipv6: reject malicious packets in ipv6_gso_segment() (bsc#1248399).
- CVE-2025-38664: ice: Fix a null pointer dereference in ice_copy_and_init_pkg() (bsc#1248628).
- CVE-2025-38685: fbdev: Fix vmalloc out-of-bounds write in fast_imageblit (bsc#1249220).
- CVE-2025-38713: hfsplus: fix slab-out-of-bounds read in hfsplus_uni2asc() (bsc#1249200).
- CVE-2025-39751: ALSA: hda/ca0132: Fix buffer overflow in add_tuning_control (bsc#1249538).
- CVE-2025-39823: KVM: x86: use array_index_nospec with indices that come from guest (bsc#1250002).

The following non-security bugs were fixed:

- Limit patch filenames to 100 characters (bsc#1249604).
- Move pesign-obs-integration requirement from kernel-syms to kernel devel subpackage (bsc#1248108).
- git_sort: Make tests independent of environment.
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.221.1.150300.18.132.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.221.1", rls:"SLES15.0SP3"))) {
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

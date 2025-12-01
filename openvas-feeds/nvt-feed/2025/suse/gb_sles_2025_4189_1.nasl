# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4189.1");
  script_cve_id("CVE-2021-4460", "CVE-2022-43945", "CVE-2022-48631", "CVE-2022-50236", "CVE-2022-50249", "CVE-2022-50280", "CVE-2022-50293", "CVE-2022-50327", "CVE-2022-50350", "CVE-2022-50356", "CVE-2022-50367", "CVE-2022-50394", "CVE-2022-50395", "CVE-2022-50423", "CVE-2022-50443", "CVE-2022-50459", "CVE-2022-50470", "CVE-2022-50481", "CVE-2022-50485", "CVE-2022-50487", "CVE-2022-50493", "CVE-2022-50496", "CVE-2022-50501", "CVE-2022-50504", "CVE-2022-50505", "CVE-2022-50509", "CVE-2022-50516", "CVE-2022-50532", "CVE-2022-50534", "CVE-2022-50536", "CVE-2022-50537", "CVE-2022-50542", "CVE-2022-50544", "CVE-2022-50549", "CVE-2022-50563", "CVE-2022-50564", "CVE-2022-50571", "CVE-2022-50581", "CVE-2023-53183", "CVE-2023-53185", "CVE-2023-53188", "CVE-2023-53191", "CVE-2023-53204", "CVE-2023-53271", "CVE-2023-53282", "CVE-2023-53289", "CVE-2023-53292", "CVE-2023-53338", "CVE-2023-53339", "CVE-2023-53373", "CVE-2023-53433", "CVE-2023-53476", "CVE-2023-53477", "CVE-2023-53484", "CVE-2023-53517", "CVE-2023-53519", "CVE-2023-53533", "CVE-2023-53540", "CVE-2023-53548", "CVE-2023-53556", "CVE-2023-53559", "CVE-2023-53564", "CVE-2023-53568", "CVE-2023-53582", "CVE-2023-53587", "CVE-2023-53589", "CVE-2023-53593", "CVE-2023-53594", "CVE-2023-53596", "CVE-2023-53603", "CVE-2023-53604", "CVE-2023-53611", "CVE-2023-53615", "CVE-2023-53619", "CVE-2023-53620", "CVE-2023-53622", "CVE-2023-53624", "CVE-2023-53635", "CVE-2023-53644", "CVE-2023-53647", "CVE-2023-53648", "CVE-2023-53650", "CVE-2023-53667", "CVE-2023-53668", "CVE-2023-53672", "CVE-2023-53675", "CVE-2023-53681", "CVE-2023-53683", "CVE-2023-53687", "CVE-2023-53695", "CVE-2023-53696", "CVE-2023-53705", "CVE-2023-53707", "CVE-2023-53715", "CVE-2023-53717", "CVE-2023-53722", "CVE-2023-53733", "CVE-2023-7324", "CVE-2024-56633", "CVE-2025-38539", "CVE-2025-38680", "CVE-2025-38691", "CVE-2025-38695", "CVE-2025-38699", "CVE-2025-38700", "CVE-2025-38714", "CVE-2025-38718", "CVE-2025-38724", "CVE-2025-39676", "CVE-2025-39702", "CVE-2025-39724", "CVE-2025-39756", "CVE-2025-39772", "CVE-2025-39812", "CVE-2025-39813", "CVE-2025-39841", "CVE-2025-39866", "CVE-2025-39876", "CVE-2025-39911", "CVE-2025-39923", "CVE-2025-39929", "CVE-2025-39931", "CVE-2025-39945", "CVE-2025-39949", "CVE-2025-39955", "CVE-2025-39968", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39997", "CVE-2025-40018", "CVE-2025-40044", "CVE-2025-40049", "CVE-2025-40078", "CVE-2025-40082", "CVE-2025-40088");
  script_tag(name:"creation_date", value:"2025-11-26 04:15:37 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-07 18:58:51 +0000 (Tue, 07 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4189-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254189-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252909");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023334.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:4189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2021-4460: drm/amdkfd: Fix UBSAN shift-out-of-bounds warning (bsc#1250764).
- CVE-2022-48631: ext4: fix bug in extents parsing when eh_entries == 0 and eh_depth > 0 (bsc#1223475).
- CVE-2022-50236: iommu/mediatek: Fix crash on isr after kexec() (bsc#1249702).
- CVE-2022-50249: memory: of: Fix refcount leak bug in of_get_ddr_timings() (bsc#1249747).
- CVE-2022-50280: pnode: terminate at peers of source (bsc#1249806).
- CVE-2022-50293: btrfs: do not BUG_ON() on ENOMEM when dropping extent items for a range (bsc#1249752).
- CVE-2022-50327: ACPI: processor: idle: Check acpi_fetch_acpi_dev() return value (bsc#1249859).
- CVE-2022-50350: scsi: target: iscsi: Fix a race condition between login_work and the login thread (bsc#1250261).
- CVE-2022-50356: net: sched: sfb: fix null pointer access issue when sfb_init() fails (bsc#1250040).
- CVE-2022-50367: fs: fix UAF/GPF bug in nilfs_mdt_destroy (bsc#1250277).
- CVE-2022-50394: i2c: ismt: Fix an out-of-bounds bug in ismt_access() (bsc#1250107).
- CVE-2022-50395: integrity: Fix memory leakage in keyring allocation error path (bsc#1250211).
- CVE-2022-50423: ACPICA: Fix use-after-free in acpi_ut_copy_ipackage_to_ipackage() (bsc#1250784).
- CVE-2022-50443: drm/rockchip: lvds: fix PM usage counter unbalance in poweron (bsc#1250768).
- CVE-2022-50459: scsi: iscsi: iscsi_tcp: Fix null-ptr-deref while calling getpeername() (bsc#1250850).
- CVE-2022-50481: cxl: fix possible null-ptr-deref in cxl_guest_init_afu<pipe>adapter() (bsc#1251051).
- CVE-2022-50485: ext4: add EXT4_IGET_BAD flag to prevent unexpected bad inode (bsc#1251197).
- CVE-2022-50505: iommu/amd: Fix pci device refcount leak in ppr_notifier() (bsc#1251086).
- CVE-2022-50516: fs: dlm: fix invalid derefence of sb_lvbptr (bsc#1251741).
- CVE-2022-50542: media: si470x: Fix use-after-free in si470x_int_in_callback() (bsc#1251330).
- CVE-2022-50571: btrfs: call __btrfs_remove_free_space_cache_locked on cache load failure (bsc#1252487).
- CVE-2023-53183: btrfs: exit gracefully if reloc roots don't match (bsc#1249863).
- CVE-2023-53185: wifi: ath9k: don't allow to overwrite ENDPOINT0 attributes (bsc#1249820).
- CVE-2023-53188: net: openvswitch: fix race on port output (bsc#1249854).
- CVE-2023-53191: irqchip/alpine-msi: Fix refcount leak in alpine_msix_init_domains (bsc#1249721).
- CVE-2023-53204: af_unix: Fix data-races around user->unix_inflight (bsc#1249682).
- CVE-2023-53271: ubi: Fix unreferenced object reported by kmemleak in ubi_resize_volume() (bsc#1249916).
- CVE-2023-53282: scsi: lpfc: Fix use-after-free KFENCE violation during sysfs firmware write (bsc#1250311).
- CVE-2023-53289: media: bdisp: Add missing check for create_workqueue (bsc#1249941).
- CVE-2023-53292: blk-mq: protect q->elevator by ->sysfs_lock in blk_mq_elv_switch_none ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.280.1", rls:"SLES12.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4188.1");
  script_cve_id("CVE-2022-43945", "CVE-2022-50327", "CVE-2022-50334", "CVE-2022-50388", "CVE-2022-50423", "CVE-2022-50432", "CVE-2022-50470", "CVE-2022-50480", "CVE-2022-50484", "CVE-2022-50487", "CVE-2022-50488", "CVE-2022-50489", "CVE-2022-50493", "CVE-2022-50494", "CVE-2022-50496", "CVE-2022-50504", "CVE-2022-50513", "CVE-2022-50516", "CVE-2022-50532", "CVE-2022-50534", "CVE-2022-50544", "CVE-2022-50546", "CVE-2022-50549", "CVE-2022-50563", "CVE-2022-50574", "CVE-2023-53282", "CVE-2023-53365", "CVE-2023-53395", "CVE-2023-53500", "CVE-2023-53559", "CVE-2023-53564", "CVE-2023-53566", "CVE-2023-53574", "CVE-2023-53619", "CVE-2023-53673", "CVE-2023-53705", "CVE-2023-53722", "CVE-2025-38476", "CVE-2025-39968", "CVE-2025-39973", "CVE-2025-40018", "CVE-2025-40082");
  script_tag(name:"creation_date", value:"2025-11-26 04:15:37 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-07 17:31:41 +0000 (Mon, 07 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4188-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254188-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252775");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023340.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:4188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50327: ACPI: processor: idle: Check acpi_fetch_acpi_dev() return value (bsc#1249859).
- CVE-2022-50334: hugetlbfs: fix null-ptr-deref in hugetlbfs_parse_param() (bsc#1249857).
- CVE-2022-50388: nvme: fix multipath crash caused by flush request when blktrace is enabled (bsc#1250293).
- CVE-2022-50423: ACPICA: Fix use-after-free in acpi_ut_copy_ipackage_to_ipackage() (bsc#1250784).
- CVE-2022-50432: kernfs: fix use-after-free in __kernfs_remove (bsc#1250851).
- CVE-2022-50488: block, bfq: fix possible uaf for 'bfqq->bic' (bsc#1251201).
- CVE-2022-50516: fs: dlm: fix invalid derefence of sb_lvbptr (bsc#1251741).
- CVE-2023-53282: scsi: lpfc: Fix use-after-free KFENCE violation during sysfs firmware write (bsc#1250311).
- CVE-2023-53365: ip6mr: Fix skb_under_panic in ip6mr_cache_report() (bsc#1249988).
- CVE-2023-53395: ACPICA: Add AML_NO_OPERAND_RESOLVE flag to Timer (bsc#1250358).
- CVE-2023-53500: xfrm: fix slab-use-after-free in decode_session6 (bsc#1250816).
- CVE-2023-53559: ip_vti: fix potential slab-use-after-free in decode_session6 (bsc#1251052).
- CVE-2023-53574: wifi: rtw88: delete timer and free skb queue when unloading (bsc#1251222).
- CVE-2023-53619: netfilter: conntrack: Avoid nf_ct_helper_hash uses after free (bsc#1251743).
- CVE-2023-53673: Bluetooth: hci_event: call disconnect callback before deleting conn (bsc#1251763).
- CVE-2023-53705: ipv6: Fix out-of-bounds access in ipv6_find_tlv() (bsc#1252554).
- CVE-2023-53722: md: raid1: fix potential OOB in raid1_remove_disk() (bsc#1252499).
- CVE-2025-38476: rpl: Fix use-after-free in rpl_do_srh_inline() (bsc#1247317).
- CVE-2025-39968: i40e: add max boundary check for VF filters (bsc#1252047).
- CVE-2025-39973: i40e: add validation for ring_len param (bsc#1252035).
- CVE-2025-40018: ipvs: Defer ip_vs_ftp unregister during netns cleanup (bsc#1252688).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.226.2.150300.18.134.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.226.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.226.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.226.2", rls:"SLES15.0SP3"))) {
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

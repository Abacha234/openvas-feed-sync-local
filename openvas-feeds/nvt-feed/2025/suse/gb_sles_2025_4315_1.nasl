# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4315.1");
  script_cve_id("CVE-2022-50116", "CVE-2022-50252", "CVE-2022-50272", "CVE-2022-50381", "CVE-2022-50409", "CVE-2023-28328", "CVE-2023-3772", "CVE-2023-53147", "CVE-2023-53282", "CVE-2023-53322", "CVE-2023-53365", "CVE-2023-53395", "CVE-2023-53705", "CVE-2023-53722", "CVE-2025-38352", "CVE-2025-38498", "CVE-2025-38617", "CVE-2025-38685", "CVE-2025-38713", "CVE-2025-39973");
  script_tag(name:"creation_date", value:"2025-12-03 04:17:29 +0000 (Wed, 03 Dec 2025)");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-02 21:26:56 +0000 (Tue, 02 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4315-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4315-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254315-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963449");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023442.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:4315-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50116: Update config files. Disable N_GSM (bsc#1244824 jsc#PED-8240).
- CVE-2022-50252: igb: Do not free q_vector unless new one was allocated (bsc#1249846).
- CVE-2022-50381: MD: add rdev reference for super write (bsc#1250257).
- CVE-2022-50409: net: If sock is dead don't access sock's sk_wq in sk_stream_wait_memory (bsc#1250392).
- CVE-2023-53282: scsi: lpfc: Fix use-after-free KFENCE violation during sysfs firmware write (bsc#1250311).
- CVE-2023-53322: scsi: qla2xxx: Wait for io return on terminate rport (bsc#1250323).
- CVE-2023-53365: ip6mr: Fix skb_under_panic in ip6mr_cache_report() (bsc#1249988).
- CVE-2023-53395: ACPICA: Add AML_NO_OPERAND_RESOLVE flag to Timer (bsc#1250358).
- CVE-2023-53705: ipv6: Fix out-of-bounds access in ipv6_find_tlv() (bsc#1252554).
- CVE-2023-53722: md: raid1: fix potential OOB in raid1_remove_disk() (bsc#1252499).
- CVE-2025-38352: posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del() (bsc#1246911).
- CVE-2025-38498: do_change_type(): refuse to operate on unmounted/not ours mounts (bsc#1247374).
- CVE-2025-38617: net/packet: fix a race in packet_set_ring() and packet_notifier() (bsc#1248621).
- CVE-2025-38685: fbdev: Fix vmalloc out-of-bounds write in fast_imageblit (bsc#1249220).
- CVE-2025-38713: hfsplus: fix slab-out-of-bounds read in hfsplus_uni2asc() (bsc#1249200).
- CVE-2025-39973: i40e: add validation for ring_len param (bsc#1252035).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.192.1", rls:"SLES11.0SP4"))) {
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

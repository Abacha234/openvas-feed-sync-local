# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0029.1");
  script_cve_id("CVE-2022-50280", "CVE-2023-53676", "CVE-2025-39967", "CVE-2025-40040", "CVE-2025-40048", "CVE-2025-40121", "CVE-2025-40154", "CVE-2025-40204");
  script_tag(name:"creation_date", value:"2026-01-06 15:16:17 +0000 (Tue, 06 Jan 2026)");
  script_version("2026-01-07T05:47:44+0000");
  script_tag(name:"last_modification", value:"2026-01-07 05:47:44 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 14:55:40 +0000 (Thu, 04 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0029-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0029-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260029-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253436");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023679.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0029-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50280: pnode: terminate at peers of source (bsc#1249806).
- CVE-2023-53676: scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show() (bsc#1251786).
- CVE-2025-40040: mm/ksm: fix flag-dropping behavior in ksm_madvise (bsc#1252780).
- CVE-2025-40048: uio_hv_generic: Let userspace take care of interrupt mask (bsc#1252862).
- CVE-2025-40121: ASoC: Intel: bytcr_rt5651: Fix invalid quirk input mapping (bsc#1253367).
- CVE-2025-40154: ASoC: Intel: bytcr_rt5640: Fix invalid quirk input mapping (bsc#1253431).
- CVE-2025-40204: sctp: Fix MAC comparison to be constant-time (bsc#1253436).
- CVE-2025-39967: fbcon: fix integer overflow in fbcon_do_set_font (bsc#1252033)

The following non-security bugs were fixed:

- scsi: storvsc: Prefer returning channel with the same CPU as on the I/O issuing CPU (bsc#1252267).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.187.3.150400.24.96.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.187.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.187.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.187.3", rls:"SLES15.0SP4"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.229959999654100");
  script_cve_id("CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-22c5cc654d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-22c5cc654d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-22c5cc654d");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-headers' package(s) announced via the FEDORA-2025-22c5cc654d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The 6.17 rc6 kernel build contains a number of important fixes across the tree. It also includes mitigations for the VMSCAPE vulnerability on x86 CPUs. This has been assigned CVE-2025-40300.");

  script_tag(name:"affected", value:"'kernel, kernel-headers' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-core", rpm:"kernel-core~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-cross-headers", rpm:"kernel-cross-headers~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-core", rpm:"kernel-debug-core~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-matched", rpm:"kernel-debug-devel-matched~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules", rpm:"kernel-debug-modules~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-core", rpm:"kernel-debug-modules-core~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-extra", rpm:"kernel-debug-modules-extra~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-modules-internal", rpm:"kernel-debug-modules-internal~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-uki-virt", rpm:"kernel-debug-uki-virt~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-uki-virt-addons", rpm:"kernel-debug-uki-virt-addons~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-aarch64", rpm:"kernel-debuginfo-common-aarch64~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-ppc64le", rpm:"kernel-debuginfo-common-ppc64le~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-s390x", rpm:"kernel-debuginfo-common-s390x~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-matched", rpm:"kernel-devel-matched~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules", rpm:"kernel-modules~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-core", rpm:"kernel-modules-core~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-extra", rpm:"kernel-modules-extra~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-extra-matched", rpm:"kernel-modules-extra-matched~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-modules-internal", rpm:"kernel-modules-internal~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-selftests-internal", rpm:"kernel-selftests-internal~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uki-virt", rpm:"kernel-uki-virt~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uki-virt-addons", rpm:"kernel-uki-virt-addons~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf", rpm:"libperf~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-debuginfo", rpm:"libperf-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libperf-devel", rpm:"libperf-devel~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf-debuginfo", rpm:"python3-perf-debuginfo~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtla", rpm:"rtla~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rv", rpm:"rv~6.17.0~0.rc6.49.fc43", rls:"FC43"))) {
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

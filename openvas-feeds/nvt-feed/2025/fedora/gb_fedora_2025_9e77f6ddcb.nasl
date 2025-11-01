# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.91017710261001009998");
  script_cve_id("CVE-2025-53605");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-9e77f6ddcb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9e77f6ddcb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9e77f6ddcb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2401160");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mirrorlist-server, rust-maxminddb, rust-monitord-exporter, rust-prometheus, rust-prometheus_exporter, rust-protobuf, rust-protobuf-codegen, rust-protobuf-parse, rust-protobuf-support' package(s) announced via the FEDORA-2025-9e77f6ddcb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update mirrorlist-server to version 3.0.8.
- Update the maxminddb crate to version 0.26.0.
- Update the prometheus crate to version 0.14.0.
- Update the protobuf and protobuf-codegen crates to version 3.7.2.
- Initial packaging of the protobuf-parse and protobuf-support crates.

This includes fixes for CVE-2025-53605 (Uncontrolled Recursion Vulnerability in the protobuf crate).");

  script_tag(name:"affected", value:"'mirrorlist-server, rust-maxminddb, rust-monitord-exporter, rust-prometheus, rust-prometheus_exporter, rust-protobuf, rust-protobuf-codegen, rust-protobuf-parse, rust-protobuf-support' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server", rpm:"mirrorlist-server~3.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debuginfo", rpm:"mirrorlist-server-debuginfo~3.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debugsource", rpm:"mirrorlist-server-debugsource~3.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord-exporter", rpm:"monitord-exporter~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord-exporter-debuginfo", rpm:"monitord-exporter-debuginfo~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb+default-devel", rpm:"rust-maxminddb+default-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb+memmap2-devel", rpm:"rust-maxminddb+memmap2-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb+mmap-devel", rpm:"rust-maxminddb+mmap-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb+simdutf8-devel", rpm:"rust-maxminddb+simdutf8-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb+unsafe-str-decode-devel", rpm:"rust-maxminddb+unsafe-str-decode-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb", rpm:"rust-maxminddb~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-maxminddb-devel", rpm:"rust-maxminddb-devel~0.26.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter+default-devel", rpm:"rust-monitord-exporter+default-devel~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter", rpm:"rust-monitord-exporter~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter-debugsource", rpm:"rust-monitord-exporter-debugsource~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter-devel", rpm:"rust-monitord-exporter-devel~0.4.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+default-devel", rpm:"rust-prometheus+default-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+gen-devel", rpm:"rust-prometheus+gen-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+libc-devel", rpm:"rust-prometheus+libc-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+nightly-devel", rpm:"rust-prometheus+nightly-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+process-devel", rpm:"rust-prometheus+process-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+procfs-devel", rpm:"rust-prometheus+procfs-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+protobuf-codegen-devel", rpm:"rust-prometheus+protobuf-codegen-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+protobuf-devel", rpm:"rust-prometheus+protobuf-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+push-devel", rpm:"rust-prometheus+push-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus+reqwest-devel", rpm:"rust-prometheus+reqwest-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus", rpm:"rust-prometheus~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus-devel", rpm:"rust-prometheus-devel~0.14.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter+default-devel", rpm:"rust-prometheus_exporter+default-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter+internal_metrics-devel", rpm:"rust-prometheus_exporter+internal_metrics-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter+lazy_static-devel", rpm:"rust-prometheus_exporter+lazy_static-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter+log-devel", rpm:"rust-prometheus_exporter+log-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter+logging-devel", rpm:"rust-prometheus_exporter+logging-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter", rpm:"rust-prometheus_exporter~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prometheus_exporter-devel", rpm:"rust-prometheus_exporter-devel~0.8.5~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf+bytes-devel", rpm:"rust-protobuf+bytes-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf+default-devel", rpm:"rust-protobuf+default-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf+with-bytes-devel", rpm:"rust-protobuf+with-bytes-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf", rpm:"rust-protobuf~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-codegen+default-devel", rpm:"rust-protobuf-codegen+default-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-codegen", rpm:"rust-protobuf-codegen~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-codegen-devel", rpm:"rust-protobuf-codegen-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-devel", rpm:"rust-protobuf-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-parse+default-devel", rpm:"rust-protobuf-parse+default-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-parse", rpm:"rust-protobuf-parse~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-parse-devel", rpm:"rust-protobuf-parse-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-support+default-devel", rpm:"rust-protobuf-support+default-devel~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-support", rpm:"rust-protobuf-support~3.7.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-protobuf-support-devel", rpm:"rust-protobuf-support-devel~3.7.2~1.fc43", rls:"FC43"))) {
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

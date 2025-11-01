# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.5979910010283593");
  script_cve_id("CVE-2025-58160");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-5acdf83593)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5acdf83593");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5acdf83593");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389401");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392998");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-uv-build, rust-secret-service, uv' package(s) announced via the FEDORA-2025-5acdf83593 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2025-58160: rebuilt `uv` and `python-uv-build` with `rust-tracing-subscriber` 0.3.20.

Initial package for `rust-secret-service` in Fedora 43 (previously a retired package).");

  script_tag(name:"affected", value:"'python-uv-build, rust-secret-service, uv' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+crypto-openssl-devel", rpm:"rust-secret-service+crypto-openssl-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+crypto-rust-devel", rpm:"rust-secret-service+crypto-rust-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+default-devel", rpm:"rust-secret-service+default-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+rt-async-io-crypto-openssl-devel", rpm:"rust-secret-service+rt-async-io-crypto-openssl-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+rt-async-io-crypto-rust-devel", rpm:"rust-secret-service+rt-async-io-crypto-rust-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+rt-tokio-crypto-openssl-devel", rpm:"rust-secret-service+rt-tokio-crypto-openssl-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service+rt-tokio-crypto-rust-devel", rpm:"rust-secret-service+rt-tokio-crypto-rust-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service", rpm:"rust-secret-service~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-secret-service-devel", rpm:"rust-secret-service-devel~5.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.8.11~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.8.11~2.fc43", rls:"FC43"))) {
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

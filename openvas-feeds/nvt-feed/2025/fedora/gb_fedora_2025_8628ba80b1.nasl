# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8628989780981");
  script_cve_id("CVE-2025-54368");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-8628ba80b1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8628ba80b1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8628ba80b1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2386891");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387092");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387194");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-uv-build, rust-h2, uv' package(s) announced via the FEDORA-2025-8628ba80b1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update uv and python-uv-build to version 0.8.8.
- Update the h2 crate to version 0.4.12.

The builds in this update also address CVE-2025-54368.");

  script_tag(name:"affected", value:"'python-uv-build, rust-h2, uv' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-h2+default-devel", rpm:"rust-h2+default-devel~0.4.12~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-h2+stream-devel", rpm:"rust-h2+stream-devel~0.4.12~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-h2+unstable-devel", rpm:"rust-h2+unstable-devel~0.4.12~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-h2", rpm:"rust-h2~0.4.12~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-h2-devel", rpm:"rust-h2-devel~0.4.12~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.8.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.8.8~1.fc43", rls:"FC43"))) {
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

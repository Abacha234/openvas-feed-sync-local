# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.261012101099477");
  script_cve_id("CVE-2025-5455");
  script_tag(name:"creation_date", value:"2025-10-28 04:05:21 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-26e2e0c477)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-26e2e0c477");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-26e2e0c477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369868");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369869");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405076");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtbase' package(s) announced via the FEDORA-2025-26e2e0c477 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix CVE-2025-5455 - QtCore Assertion Failure Denial of Service");

  script_tag(name:"affected", value:"'qt5-qtbase' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase", rpm:"qt5-qtbase~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-common", rpm:"qt5-qtbase-common~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-debuginfo", rpm:"qt5-qtbase-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-debugsource", rpm:"qt5-qtbase-debugsource~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-devel", rpm:"qt5-qtbase-devel~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-devel-debuginfo", rpm:"qt5-qtbase-devel-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-examples", rpm:"qt5-qtbase-examples~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-examples-debuginfo", rpm:"qt5-qtbase-examples-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-gui", rpm:"qt5-qtbase-gui~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-gui-debuginfo", rpm:"qt5-qtbase-gui-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-ibase", rpm:"qt5-qtbase-ibase~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-ibase-debuginfo", rpm:"qt5-qtbase-ibase-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-mysql", rpm:"qt5-qtbase-mysql~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-mysql-debuginfo", rpm:"qt5-qtbase-mysql-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-odbc", rpm:"qt5-qtbase-odbc~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-odbc-debuginfo", rpm:"qt5-qtbase-odbc-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-postgresql", rpm:"qt5-qtbase-postgresql~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-postgresql-debuginfo", rpm:"qt5-qtbase-postgresql-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-private-devel", rpm:"qt5-qtbase-private-devel~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-static", rpm:"qt5-qtbase-static~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-tds", rpm:"qt5-qtbase-tds~5.15.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtbase-tds-debuginfo", rpm:"qt5-qtbase-tds-debuginfo~5.15.17~2.fc41", rls:"FC41"))) {
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

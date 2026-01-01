# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.96977081019795");
  script_cve_id("CVE-2025-14174", "CVE-2025-43501", "CVE-2025-43529", "CVE-2025-43531", "CVE-2025-43535", "CVE-2025-43536", "CVE-2025-43541");
  script_tag(name:"creation_date", value:"2025-12-19 09:15:55 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-96a708ea95)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-96a708ea95");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-96a708ea95");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423173");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423292");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423296");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423302");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423306");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423310");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk' package(s) announced via the FEDORA-2025-96a708ea95 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Correctly handle the program name passed to the sleep disabler.
* Ensure GStreamer is initialized before using the Quirks.
* Fix several crashes and rendering issues.
* Fix CVE-2025-14174, CVE-2025-43501, CVE-2025-43529, CVE-2025-43531, CVE-2025-43535, CVE-2025-43536, CVE-2025-43541");

  script_tag(name:"affected", value:"'webkitgtk' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1", rpm:"javascriptcoregtk4.1~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-debuginfo", rpm:"javascriptcoregtk4.1-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel", rpm:"javascriptcoregtk4.1-devel~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk4.1-devel-debuginfo", rpm:"javascriptcoregtk4.1-devel-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0", rpm:"javascriptcoregtk6.0~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-debuginfo", rpm:"javascriptcoregtk6.0-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel", rpm:"javascriptcoregtk6.0-devel~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"javascriptcoregtk6.0-devel-debuginfo", rpm:"javascriptcoregtk6.0-devel-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-debuginfo", rpm:"webkit2gtk4.1-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel", rpm:"webkit2gtk4.1-devel~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-devel-debuginfo", rpm:"webkit2gtk4.1-devel-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-doc", rpm:"webkit2gtk4.1-doc~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-debugsource", rpm:"webkitgtk-debugsource~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-debuginfo", rpm:"webkitgtk6.0-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel", rpm:"webkitgtk6.0-devel~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-devel-debuginfo", rpm:"webkitgtk6.0-devel-debuginfo~2.50.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-doc", rpm:"webkitgtk6.0-doc~2.50.4~1.fc43", rls:"FC43"))) {
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

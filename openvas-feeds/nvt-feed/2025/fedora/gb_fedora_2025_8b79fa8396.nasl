# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.89879102978396");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-8b79fa8396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-8b79fa8396");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-8b79fa8396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272332");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302543");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302544");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329714");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-cursive, rust-cursive0.20, rust-cursive_core, rust-cursive_core0.3, rust-ncurses, rust-ncurses5' package(s) announced via the FEDORA-2025-8b79fa8396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the cursive crate to version 0.21.1 and add a compat package for version 0.20.
- Update the cursive_core crate to version 0.4.6 and add a compat package for version 0.3.
- Update the ncurses crate to version 6.0.1 and add a compat package for version 5.");

  script_tag(name:"affected", value:"'rust-cursive, rust-cursive0.20, rust-cursive_core, rust-cursive_core0.3, rust-ncurses, rust-ncurses5' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+builder-devel", rpm:"rust-cursive+builder-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+crossterm-backend-devel", rpm:"rust-cursive+crossterm-backend-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+default-devel", rpm:"rust-cursive+default-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+doc-cfg-devel", rpm:"rust-cursive+doc-cfg-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+ncurses-backend-devel", rpm:"rust-cursive+ncurses-backend-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+pancurses-backend-devel", rpm:"rust-cursive+pancurses-backend-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+termion-backend-devel", rpm:"rust-cursive+termion-backend-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive+toml-devel", rpm:"rust-cursive+toml-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive", rpm:"rust-cursive~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive-devel", rpm:"rust-cursive-devel~0.21.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+crossterm-backend-devel", rpm:"rust-cursive0.20+crossterm-backend-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+crossterm-devel", rpm:"rust-cursive0.20+crossterm-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+default-devel", rpm:"rust-cursive0.20+default-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+doc-cfg-devel", rpm:"rust-cursive0.20+doc-cfg-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+maplit-devel", rpm:"rust-cursive0.20+maplit-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+ncurses-backend-devel", rpm:"rust-cursive0.20+ncurses-backend-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+ncurses-devel", rpm:"rust-cursive0.20+ncurses-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+pancurses-backend-devel", rpm:"rust-cursive0.20+pancurses-backend-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+pancurses-devel", rpm:"rust-cursive0.20+pancurses-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+term_size-devel", rpm:"rust-cursive0.20+term_size-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+termion-backend-devel", rpm:"rust-cursive0.20+termion-backend-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+termion-devel", rpm:"rust-cursive0.20+termion-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+toml-devel", rpm:"rust-cursive0.20+toml-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20+unstable_scroll-devel", rpm:"rust-cursive0.20+unstable_scroll-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20", rpm:"rust-cursive0.20~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive0.20-devel", rpm:"rust-cursive0.20-devel~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core+builder-devel", rpm:"rust-cursive_core+builder-devel~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core+default-devel", rpm:"rust-cursive_core+default-devel~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core+doc-cfg-devel", rpm:"rust-cursive_core+doc-cfg-devel~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core+toml-devel", rpm:"rust-cursive_core+toml-devel~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core", rpm:"rust-cursive_core~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core-devel", rpm:"rust-cursive_core-devel~0.4.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3+default-devel", rpm:"rust-cursive_core0.3+default-devel~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3+doc-cfg-devel", rpm:"rust-cursive_core0.3+doc-cfg-devel~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3+toml-devel", rpm:"rust-cursive_core0.3+toml-devel~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3+unstable_scroll-devel", rpm:"rust-cursive_core0.3+unstable_scroll-devel~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3", rpm:"rust-cursive_core0.3~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cursive_core0.3-devel", rpm:"rust-cursive_core0.3-devel~0.3.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+default-devel", rpm:"rust-ncurses+default-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+extended_colors-devel", rpm:"rust-ncurses+extended_colors-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+menu-devel", rpm:"rust-ncurses+menu-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+mouse_v1-devel", rpm:"rust-ncurses+mouse_v1-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+panel-devel", rpm:"rust-ncurses+panel-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+wide-devel", rpm:"rust-ncurses+wide-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses+wide_chtype-devel", rpm:"rust-ncurses+wide_chtype-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses", rpm:"rust-ncurses~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses-devel", rpm:"rust-ncurses-devel~6.0.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+default-devel", rpm:"rust-ncurses5+default-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+extended_colors-devel", rpm:"rust-ncurses5+extended_colors-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+menu-devel", rpm:"rust-ncurses5+menu-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+mouse_v1-devel", rpm:"rust-ncurses5+mouse_v1-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+panel-devel", rpm:"rust-ncurses5+panel-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+wide-devel", rpm:"rust-ncurses5+wide-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5+wide_chtype-devel", rpm:"rust-ncurses5+wide_chtype-devel~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5", rpm:"rust-ncurses5~5.101.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ncurses5-devel", rpm:"rust-ncurses5-devel~5.101.0~1.fc43", rls:"FC43"))) {
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

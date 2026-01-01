# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.6210012561298");
  script_cve_id("CVE-2025-12385");
  script_tag(name:"creation_date", value:"2025-12-17 10:50:36 +0000 (Wed, 17 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-62d125612b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-62d125612b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-62d125612b");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-qtdeclarative' package(s) announced via the FEDORA-2025-62d125612b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-12385: Fix improper validation of img tag size in Text component parser");

  script_tag(name:"affected", value:"'qt6-qtdeclarative' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative", rpm:"qt6-qtdeclarative~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-debuginfo", rpm:"qt6-qtdeclarative-debuginfo~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-debugsource", rpm:"qt6-qtdeclarative-debugsource~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-devel", rpm:"qt6-qtdeclarative-devel~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-devel-debuginfo", rpm:"qt6-qtdeclarative-devel-debuginfo~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-examples", rpm:"qt6-qtdeclarative-examples~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-examples-debuginfo", rpm:"qt6-qtdeclarative-examples-debuginfo~6.9.3~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtdeclarative-static", rpm:"qt6-qtdeclarative-static~6.9.3~2.fc42", rls:"FC42"))) {
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

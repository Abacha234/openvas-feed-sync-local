# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.4199960783102");
  script_cve_id("CVE-2024-13978", "CVE-2025-4638", "CVE-2025-64505", "CVE-2025-64506", "CVE-2025-64720", "CVE-2025-65018", "CVE-2025-66293", "CVE-2025-8176", "CVE-2025-8177", "CVE-2025-8851", "CVE-2025-8961", "CVE-2025-9165", "CVE-2025-9900");
  script_tag(name:"creation_date", value:"2025-12-29 04:25:42 +0000 (Mon, 29 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-21 14:10:50 +0000 (Tue, 21 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-419c60783f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-419c60783f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-419c60783f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337800");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366434");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2383825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2383831");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2385697");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2386206");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387669");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388598");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417441");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417470");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417476");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417488");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417492");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418415");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418427");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418740");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423630");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tkimg' package(s) announced via the FEDORA-2025-419c60783f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.1.0. Update bundled libpng, libtiff, to latest versions. Built against TCL/TK 9. Fix FTBFS.");

  script_tag(name:"affected", value:"'tkimg' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"tkimg", rpm:"tkimg~2.1.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkimg-debuginfo", rpm:"tkimg-debuginfo~2.1.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkimg-debugsource", rpm:"tkimg-debugsource~2.1.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkimg-devel", rpm:"tkimg-devel~2.1.0~1.fc42", rls:"FC42"))) {
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

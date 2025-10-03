# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.39710246459597");
  script_cve_id("CVE-2025-6965");
  script_tag(name:"creation_date", value:"2025-10-02 04:05:15 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-22 17:06:21 +0000 (Tue, 22 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3af464595a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3af464595a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3af464595a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2380241");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite' package(s) announced via the FEDORA-2025-3af464595a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cve fixes");

  script_tag(name:"affected", value:"'sqlite' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"lemon", rpm:"lemon~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemon-debuginfo", rpm:"lemon-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite", rpm:"sqlite~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-analyzer", rpm:"sqlite-analyzer~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-analyzer-debuginfo", rpm:"sqlite-analyzer-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-debug", rpm:"sqlite-debug~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-debug-debuginfo", rpm:"sqlite-debug-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-debuginfo", rpm:"sqlite-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-debugsource", rpm:"sqlite-debugsource~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-devel", rpm:"sqlite-devel~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-doc", rpm:"sqlite-doc~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-libs", rpm:"sqlite-libs~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-libs-debuginfo", rpm:"sqlite-libs-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-tcl", rpm:"sqlite-tcl~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-tcl-debuginfo", rpm:"sqlite-tcl-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-tools", rpm:"sqlite-tools~3.47.2~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite-tools-debuginfo", rpm:"sqlite-tools-debuginfo~3.47.2~5.fc42", rls:"FC42"))) {
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

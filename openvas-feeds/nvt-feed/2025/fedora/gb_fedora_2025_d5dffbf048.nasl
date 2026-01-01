# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.100510010210298102048");
  script_cve_id("CVE-2025-12084", "CVE-2025-6075", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2025-12-17 10:50:36 +0000 (Wed, 17 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-16 21:13:09 +0000 (Tue, 16 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-d5dffbf048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d5dffbf048");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d5dffbf048");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402875");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2413058");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421620");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.14' package(s) announced via the FEDORA-2025-d5dffbf048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the second maintenance release of Python 3.14");

  script_tag(name:"affected", value:"'python3.14' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.14", rpm:"python3.14~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debug", rpm:"python3.14-debug~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debuginfo", rpm:"python3.14-debuginfo~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-debugsource", rpm:"python3.14-debugsource~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-devel", rpm:"python3.14-devel~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading", rpm:"python3.14-freethreading~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-debug", rpm:"python3.14-freethreading-debug~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-devel", rpm:"python3.14-freethreading-devel~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-idle", rpm:"python3.14-freethreading-idle~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-libs", rpm:"python3.14-freethreading-libs~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-test", rpm:"python3.14-freethreading-test~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-freethreading-tkinter", rpm:"python3.14-freethreading-tkinter~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-idle", rpm:"python3.14-idle~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-libs", rpm:"python3.14-libs~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-test", rpm:"python3.14-test~3.14.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.14-tkinter", rpm:"python3.14-tkinter~3.14.2~1.fc42", rls:"FC42"))) {
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

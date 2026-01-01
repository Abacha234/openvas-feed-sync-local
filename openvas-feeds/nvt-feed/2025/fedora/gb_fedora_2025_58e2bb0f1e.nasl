# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.581012989801021101");
  script_cve_id("CVE-2025-66034");
  script_tag(name:"creation_date", value:"2025-12-22 04:21:57 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-03 21:50:20 +0000 (Wed, 03 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-58e2bb0f1e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-58e2bb0f1e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-58e2bb0f1e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421330");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fonttools, python-unicodedata2' package(s) announced via the FEDORA-2025-58e2bb0f1e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 17.0.0 version (#2412270)
Update fonttools 4.61.0");

  script_tag(name:"affected", value:"'fonttools, python-unicodedata2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"fonttools", rpm:"fonttools~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fonttools-debugsource", rpm:"fonttools-debugsource~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-unicodedata2", rpm:"python-unicodedata2~17.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-unicodedata2-debugsource", rpm:"python-unicodedata2-debugsource~17.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+graphite", rpm:"python3-fonttools+graphite~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+interpolatable", rpm:"python3-fonttools+interpolatable~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+lxml", rpm:"python3-fonttools+lxml~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+plot", rpm:"python3-fonttools+plot~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+repacker", rpm:"python3-fonttools+repacker~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+symfont", rpm:"python3-fonttools+symfont~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+type1", rpm:"python3-fonttools+type1~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+ufo", rpm:"python3-fonttools+ufo~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+unicode", rpm:"python3-fonttools+unicode~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools+woff", rpm:"python3-fonttools+woff~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools", rpm:"python3-fonttools~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fonttools-debuginfo", rpm:"python3-fonttools-debuginfo~4.61.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unicodedata2", rpm:"python3-unicodedata2~17.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unicodedata2-debuginfo", rpm:"python3-unicodedata2-debuginfo~17.0.0~1.fc42", rls:"FC42"))) {
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

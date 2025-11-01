# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.991001028149962");
  script_cve_id("CVE-2025-54080", "CVE-2025-55304");
  script_tag(name:"creation_date", value:"2025-10-15 04:05:27 +0000 (Wed, 15 Oct 2025)");
  script_version("2025-10-15T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-10-15 05:39:06 +0000 (Wed, 15 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-99df814c62)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-99df814c62");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-99df814c62");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2391818");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2391840");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inih, mingw-exiv2' package(s) announced via the FEDORA-2025-99df814c62 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to exiv2-0.28.7, fixes CVE-2025-54080 and CVE-2025-55304.");

  script_tag(name:"affected", value:"'inih, mingw-exiv2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"inih", rpm:"inih~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inih-cpp", rpm:"inih-cpp~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inih-cpp-debuginfo", rpm:"inih-cpp-debuginfo~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inih-debuginfo", rpm:"inih-debuginfo~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inih-debugsource", rpm:"inih-debugsource~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inih-devel", rpm:"inih-devel~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-exiv2", rpm:"mingw-exiv2~0.28.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-exiv2", rpm:"mingw32-exiv2~0.28.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-exiv2-debuginfo", rpm:"mingw32-exiv2-debuginfo~0.28.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-inih", rpm:"mingw32-inih~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-inih-debuginfo", rpm:"mingw32-inih-debuginfo~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-exiv2", rpm:"mingw64-exiv2~0.28.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-exiv2-debuginfo", rpm:"mingw64-exiv2-debuginfo~0.28.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-inih", rpm:"mingw64-inih~62~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-inih-debuginfo", rpm:"mingw64-inih-debuginfo~62~1.fc42", rls:"FC42"))) {
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

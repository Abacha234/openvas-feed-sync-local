# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98210010236987097");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-14512");
  script_tag(name:"creation_date", value:"2025-12-23 04:19:57 +0000 (Tue, 23 Dec 2025)");
  script_version("2025-12-24T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-24 05:46:55 +0000 (Wed, 24 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 15:15:51 +0000 (Wed, 26 Nov 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b2df36b70a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b2df36b70a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b2df36b70a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417052");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419111");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421343");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-glib2' package(s) announced via the FEDORA-2025-b2df36b70a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to glib-2.84.4 and backport fixes for CVE-2025-13601, CVE-2025-14087 and CVE-2025-14512.");

  script_tag(name:"affected", value:"'mingw-glib2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-glib2", rpm:"mingw-glib2~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-glib2", rpm:"mingw32-glib2~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-glib2-debuginfo", rpm:"mingw32-glib2-debuginfo~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-glib2-static", rpm:"mingw32-glib2-static~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-glib2", rpm:"mingw64-glib2~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-glib2-debuginfo", rpm:"mingw64-glib2-debuginfo~2.84.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-glib2-static", rpm:"mingw64-glib2-static~2.84.4~1.fc42", rls:"FC42"))) {
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

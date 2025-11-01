# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.928594297999");
  script_cve_id("CVE-2024-47081", "CVE-2025-47273", "CVE-2025-50181");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-12 16:29:01 +0000 (Thu, 12 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-9285942ac9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9285942ac9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9285942ac9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2367430");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372476");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373817");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376234");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy' package(s) announced via the FEDORA-2025-9285942ac9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for pypy-7.3.20-2.fc43.

##### **Changelog**

```
* Thu Jul 10 2025 Charalampos Stratakis <cstratak@redhat.com> - 7.3.20-1
- Update to 7.3.20
- Fixes: rhbz#2376234
* Thu Jul 10 2025 Charalampos Stratakis <cstratak@redhat.com> - 7.3.19-2
- Security fixes for CVE-2025-47273, CVE-2024-47081 and CVE-2025-50181
- Fixes: rhbz#2367430, rhbz#2372476, rhbz#2373817

```");

  script_tag(name:"affected", value:"'pypy' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"pypy", rpm:"pypy~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debuginfo", rpm:"pypy-debuginfo~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debugsource", rpm:"pypy-debugsource~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debugsource-debuginfo", rpm:"pypy-debugsource-debuginfo~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-devel", rpm:"pypy-devel~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-libs", rpm:"pypy-libs~7.3.20~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-libs-debuginfo", rpm:"pypy-libs-debuginfo~7.3.20~2.fc43", rls:"FC43"))) {
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

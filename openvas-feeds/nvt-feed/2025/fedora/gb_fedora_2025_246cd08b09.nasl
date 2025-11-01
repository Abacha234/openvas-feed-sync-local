# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.24699100089809");
  script_cve_id("CVE-2024-12243");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 16:15:37 +0000 (Mon, 10 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-246cd08b09)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-246cd08b09");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-246cd08b09");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292594");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332571");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2344440");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls, nettle' package(s) announced via the FEDORA-2025-246cd08b09 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update gnutls and nettle to the latest upstream release.
The gnutls build also fixes CVE-2024-12243.

----

Includes build fixes
```
Changelog
* Wed Feb 05 2025 Yaakov Selkowitz <yselkowi@redhat.com> - 3.8.8-4
- Fix ELN build
* Thu Jan 23 2025 Daiki Ueno <dueno@redhat.com> - 3.8.8-3
- Disable GOST in RHEL-9 or later
```");

  script_tag(name:"affected", value:"'gnutls, nettle' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-c++", rpm:"gnutls-c++~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-c++-debuginfo", rpm:"gnutls-c++-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-dane", rpm:"gnutls-dane~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-dane-debuginfo", rpm:"gnutls-dane-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-fips", rpm:"gnutls-fips~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-utils-debuginfo", rpm:"gnutls-utils-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gnutls", rpm:"mingw32-gnutls~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gnutls-debuginfo", rpm:"mingw32-gnutls-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gnutls", rpm:"mingw64-gnutls~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gnutls-debuginfo", rpm:"mingw64-gnutls-debuginfo~3.8.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle", rpm:"nettle~3.10.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle-debuginfo", rpm:"nettle-debuginfo~3.10.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle-debugsource", rpm:"nettle-debugsource~3.10.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nettle-devel", rpm:"nettle-devel~3.10.1~1.fc43", rls:"FC43"))) {
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

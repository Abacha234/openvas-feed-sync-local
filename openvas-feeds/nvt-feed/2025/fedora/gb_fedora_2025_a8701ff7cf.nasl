# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.978701102102799102");
  script_cve_id("CVE-2024-21506", "CVE-2024-5629");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 18:31:05 +0000 (Tue, 18 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a8701ff7cf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a8701ff7cf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a8701ff7cf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273860");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290587");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_42_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pymongo' package(s) announced via the FEDORA-2025-a8701ff7cf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for python-pymongo-4.9.1-3.fc43.

##### **Changelog**

```
* Thu Feb 6 2025 Orion Poplawski <orion@nwra.com> - 4.9.1-3
- Use pytest for tests
- Drop snappy extra on i686
* Sat Jan 18 2025 Fedora Release Engineering <releng@fedoraproject.org> - 4.9.1-2
- Rebuilt for [link moved to references]
* Fri Sep 20 2024 Jerry James <loganjerry@gmail.com> - 4.9.1-1
- Version 4.9.1
- Fixes CVE-2024-21506 (rhbz#2273860)
- Fixes CVE-2024-5629 (rhbz#2290587)
- Modernize the spec file
- Fix up the license information
- Add check script
- Package the ocsp, snappy, and zstd extras
- Build docs for Fedora only
- Permit use of pytest-asyncio 0.23 until Fedora can catch up
* Wed Sep 4 2024 Miroslav Suchy <msuchy@redhat.com> - 4.2.0-9
- convert license to SPDX

```");

  script_tag(name:"affected", value:"'python-pymongo' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pymongo", rpm:"python-pymongo~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pymongo-debuginfo", rpm:"python-pymongo-debuginfo~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pymongo-debugsource", rpm:"python-pymongo-debugsource~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pymongo-doc", rpm:"python-pymongo-doc~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bson", rpm:"python3-bson~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bson-debuginfo", rpm:"python3-bson-debuginfo~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo+ocsp", rpm:"python3-pymongo+ocsp~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo+snappy", rpm:"python3-pymongo+snappy~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo+zstd", rpm:"python3-pymongo+zstd~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo", rpm:"python3-pymongo~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo-debuginfo", rpm:"python3-pymongo-debuginfo~4.9.1~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pymongo-gridfs", rpm:"python3-pymongo-gridfs~4.9.1~3.fc43", rls:"FC43"))) {
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

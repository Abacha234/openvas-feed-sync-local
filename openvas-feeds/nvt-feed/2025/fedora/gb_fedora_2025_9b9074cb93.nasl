# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9989074999893");
  script_cve_id("CVE-2025-22870");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-9b9074cb93)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9b9074cb93");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9b9074cb93");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2321697");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2340461");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352244");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358709");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_42_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-alertmanager' package(s) announced via the FEDORA-2025-9b9074cb93 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-prometheus-alertmanager-0.28.1-1.fc43.

##### **Changelog**

```
* Thu Jul 10 2025 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 0.28.1-1
- Update to 0.28.1 - Closes rhbz#2358709 rhbz#2352244 rhbz#2340461
 rhbz#2321697
* Fri Jan 17 2025 Fedora Release Engineering <releng@fedoraproject.org> - 0.27.0-3
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'golang-github-prometheus-alertmanager' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.28.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debuginfo", rpm:"golang-github-prometheus-alertmanager-debuginfo~0.28.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debugsource", rpm:"golang-github-prometheus-alertmanager-debugsource~0.28.1~1.fc43", rls:"FC43"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.55197101100076101");
  script_cve_id("CVE-2024-38824", "CVE-2025-22236", "CVE-2025-22239", "CVE-2025-22240", "CVE-2025-22241", "CVE-2025-22242");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-10 00:34:26 +0000 (Thu, 10 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-551aed076e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-551aed076e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-551aed076e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366381");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372731");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372732");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372733");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372734");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372741");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372745");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372746");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372748");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372752");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372753");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372774");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2372776");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the FEDORA-2025-551aed076e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for salt-3007.4-2.fc43.

##### **Changelog**

```
* Thu Jun 19 2025 Robby Callicotte <rcallicotte@fedoraproject.org> - 3007.4-2
- Updated sources
* Thu Jun 19 2025 Robby Callicotte <rcallicotte@fedoraproject.org> - 3007.4-1
- Update to 3007.4 RHBZ#2366381 - Resolves CVE-2024-38824 RHBZ#2372731 -
 Resolves CVE-2024-38824 RHBZ#2372733 - Resolves CVE-2025-22239
 RHBZ#2372732 - Resolves CVE-2025-22239 RHBZ#2372734 - Resolves
 CVE-2025-22236 RHBZ#2372774 - Resolves CVE-2025-22236 RHBZ#2372776 -
 Resolves CVE-2025-22242 RHBZ#2372741 - Resolves CVE-2025-22242
 RHBZ#2372745 - Resolves CVE-2025-22240 RHBZ#2372746 - Resolves
 CVE-2025-22241 RHBZ#2372748 - Resolves CVE-2025-22240 RHBZ#2372752 -
 Resolves CVE-2025-22241 RHBZ#2372753

```");

  script_tag(name:"affected", value:"'salt' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3007.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3007.4~2.fc43", rls:"FC43"))) {
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

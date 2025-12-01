# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.983399921019797100");
  script_cve_id("CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-b339c2eaad)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b339c2eaad");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b339c2eaad");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407594");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407865");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408141");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408575");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408639");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408702");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409049");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409332");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409611");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409997");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410284");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410562");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411197");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411460");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412525");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412677");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412757");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.33' package(s) announced via the FEDORA-2025-b339c2eaad advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release 1.33.6
- Resolves: rhbz#2407594, rhbz#2407865, rhbz#2408141, rhbz#2408575
- Resolves: rhbz#2408639, rhbz#2408702, rhbz#2409049, rhbz#2409332
- Resolves: rhbz#2409611, rhbz#2409997, rhbz#2410284, rhbz#2410562
- Resolves: rhbz#2410929, rhbz#2411197, rhbz#2411460, rhbz#2412525
- Resolves: rhbz#2412677, rhbz#2412757");

  script_tag(name:"affected", value:"'cri-o1.33' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33", rpm:"cri-o1.33~1.33.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33-debuginfo", rpm:"cri-o1.33-debuginfo~1.33.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.33-debugsource", rpm:"cri-o1.33-debugsource~1.33.6~1.fc43", rls:"FC43"))) {
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

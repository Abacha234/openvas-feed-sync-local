# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.986422100641029");
  script_cve_id("CVE-2025-11001", "CVE-2025-53816", "CVE-2025-53817", "CVE-2025-55188");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-24 15:07:32 +0000 (Mon, 24 Nov 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b6422d64f9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b6422d64f9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b6422d64f9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2376517");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381822");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387643");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412315");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2416899");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2416900");

  script_tag(name:"summary", value:"The remote host is missing an update for the '7zip' package(s) announced via the FEDORA-2025-b6422d64f9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various CVE fixes, most importantly CVE-2025-11001

This also backports the Debian patch (PR unfortunately stalled upstream, with no communication from upstream developers) to not echo passwords when dealing with encrypted archives.");

  script_tag(name:"affected", value:"'7zip' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"7zip", rpm:"7zip~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-debuginfo", rpm:"7zip-debuginfo~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-debugsource", rpm:"7zip-debugsource~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-reduced", rpm:"7zip-reduced~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-reduced-debuginfo", rpm:"7zip-reduced-debuginfo~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-standalone", rpm:"7zip-standalone~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-standalone-all", rpm:"7zip-standalone-all~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-standalone-all-debuginfo", rpm:"7zip-standalone-all-debuginfo~25.01~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"7zip-standalone-debuginfo", rpm:"7zip-standalone-debuginfo~25.01~1.fc43", rls:"FC43"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10010097924100757");
  script_cve_id("CVE-2025-11001", "CVE-2025-53816", "CVE-2025-53817", "CVE-2025-55188", "CVE-2025-9136");
  script_tag(name:"creation_date", value:"2025-12-25 04:19:22 +0000 (Thu, 25 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-12 14:55:08 +0000 (Fri, 12 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-dda924d757)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-dda924d757");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dda924d757");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290413");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381834");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381837");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387650");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389431");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2415383");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418241");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418245");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'retroarch' package(s) announced via the FEDORA-2025-dda924d757 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.22.0");

  script_tag(name:"affected", value:"'retroarch' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"retroarch", rpm:"retroarch~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-assets", rpm:"retroarch-assets~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-database", rpm:"retroarch-database~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-debuginfo", rpm:"retroarch-debuginfo~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-debugsource", rpm:"retroarch-debugsource~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-filters", rpm:"retroarch-filters~1.22.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"retroarch-filters-debuginfo", rpm:"retroarch-filters-debuginfo~1.22.0~1.fc42", rls:"FC42"))) {
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

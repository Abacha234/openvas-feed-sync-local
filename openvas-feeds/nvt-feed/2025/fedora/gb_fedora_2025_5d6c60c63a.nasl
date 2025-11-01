# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.510069960996397");
  script_cve_id("CVE-2025-43859");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-5d6c60c63a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5d6c60c63a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5d6c60c63a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361973");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362227");
  script_xref(name:"URL", value:"https://github.com/encode/httpcore/blob/1.0.9/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/python-hyper/h11/blob/v0.16.0/docs/source/changes.rst");
  script_xref(name:"URL", value:"https://github.com/python-hyper/h11/security/advisories/GHSA-vqfr-h8mv-ghfj");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-h11, python-httpcore' package(s) announced via the FEDORA-2025-5d6c60c63a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update python-h11 to version 0.16.0 to resolve CVE-2025-43859. This also requires updating python-httpcore to version 1.0.9 to raise it's upper dependency bound on h11.

* [links moved to references]");

  script_tag(name:"affected", value:"'python-h11, python-httpcore' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-h11", rpm:"python-h11~0.16.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-httpcore", rpm:"python-httpcore~1.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-h11", rpm:"python3-h11~0.16.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-httpcore+http2", rpm:"python3-httpcore+http2~1.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-httpcore+socks", rpm:"python3-httpcore+socks~1.0.9~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-httpcore", rpm:"python3-httpcore~1.0.9~1.fc43", rls:"FC43"))) {
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

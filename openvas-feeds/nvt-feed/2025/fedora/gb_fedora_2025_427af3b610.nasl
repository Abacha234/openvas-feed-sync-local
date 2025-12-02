# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.42797102398610");
  script_cve_id("CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723");
  script_tag(name:"creation_date", value:"2025-12-01 04:25:36 +0000 (Mon, 01 Dec 2025)");
  script_version("2025-12-01T05:45:26+0000");
  script_tag(name:"last_modification", value:"2025-12-01 05:45:26 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-427af3b610)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-427af3b610");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-427af3b610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408323");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409796");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410746");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411642");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'migrate' package(s) announced via the FEDORA-2025-427af3b610 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to 4.19.0
- Address CVEs by rebuilding with Go 1.25.4");

  script_tag(name:"affected", value:"'migrate' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-migrate-4-devel", rpm:"golang-github-migrate-4-devel~4.19.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"migrate", rpm:"migrate~4.19.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"migrate-debuginfo", rpm:"migrate-debuginfo~4.19.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"migrate-debugsource", rpm:"migrate-debugsource~4.19.0~1.fc43", rls:"FC43"))) {
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

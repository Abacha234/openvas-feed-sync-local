# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3979987999970101");
  script_cve_id("CVE-2018-15853", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15863");
  script_tag(name:"creation_date", value:"2025-12-08 04:15:26 +0000 (Mon, 08 Dec 2025)");
  script_version("2025-12-08T05:46:14+0000");
  script_tag(name:"last_modification", value:"2025-12-08 05:46:14 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 16:47:02 +0000 (Tue, 23 Oct 2018)");

  script_name("Fedora: Security Advisory (FEDORA-2025-3a9b79ca0e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3a9b79ca0e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3a9b79ca0e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418046");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418048");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418050");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418053");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xkbcomp' package(s) announced via the FEDORA-2025-3a9b79ca0e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xkbcomp 1.5.0 (CVE-2018-15853, CVE-2018-15859, CVE-2018-15861, CVE-2018-15863)");

  script_tag(name:"affected", value:"'xkbcomp' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp", rpm:"xkbcomp~1.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp-debuginfo", rpm:"xkbcomp-debuginfo~1.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp-debugsource", rpm:"xkbcomp-debugsource~1.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp-devel", rpm:"xkbcomp-devel~1.5.0~1.fc43", rls:"FC43"))) {
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

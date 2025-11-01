# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.100210039751029779");
  script_cve_id("CVE-2023-30608", "CVE-2024-4340");
  script_tag(name:"creation_date", value:"2025-10-27 04:10:53 +0000 (Mon, 27 Oct 2025)");
  script_version("2025-10-28T05:40:26+0000");
  script_tag(name:"last_modification", value:"2025-10-28 05:40:26 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 03:50:29 +0000 (Fri, 28 Apr 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-d2d3a5fa79)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d2d3a5fa79");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d2d3a5fa79");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402812");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402813");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-sqlparse' package(s) announced via the FEDORA-2025-d2d3a5fa79 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update backports the upstream fixes for CVE-2023-30608 and CVE-2024-4340. It also enables the test suite and corrects the SPDX license identifier.");

  script_tag(name:"affected", value:"'python-sqlparse' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-sqlparse", rpm:"python-sqlparse~0.4.2~14.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-sqlparse", rpm:"python3-sqlparse~0.4.2~14.fc42", rls:"FC42"))) {
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

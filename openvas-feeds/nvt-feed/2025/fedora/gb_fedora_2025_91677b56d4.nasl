# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9167798561004");
  script_cve_id("CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-91677b56d4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-91677b56d4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-91677b56d4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407593");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407864");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408140");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408571");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408638");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408701");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409048");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409331");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409996");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410561");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410928");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411196");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411459");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412676");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412756");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.32' package(s) announced via the FEDORA-2025-91677b56d4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to release v1.32.10");

  script_tag(name:"affected", value:"'cri-o1.32' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32", rpm:"cri-o1.32~1.32.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32-debuginfo", rpm:"cri-o1.32-debuginfo~1.32.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32-debugsource", rpm:"cri-o1.32-debugsource~1.32.10~1.fc42", rls:"FC42"))) {
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

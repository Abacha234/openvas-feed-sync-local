# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.7231010102100898100");
  script_cve_id("CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-723e0fd8bd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-723e0fd8bd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-723e0fd8bd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407866");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408142");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408577");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408640");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409050");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409333");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409612");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409998");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410285");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410563");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410930");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411198");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411461");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412526");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412678");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412758");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.34' package(s) announced via the FEDORA-2025-723e0fd8bd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release 1.34.2
- Resolves: rhbz#2407595, rhbz#2407866, rhbz#2408142, rhbz#2408577
- Resolves: rhbz#2408640, rhbz#2408703, rhbz#2409050, rhbz#2409333
- Resolves: rhbz#2409612, rhbz#2409998, rhbz#2410285, rhbz#2410563
- Resolves: rhbz#2410930, rhbz#2411198, rhbz#2411461, rhbz#2412526
- Resolves: rhbz#2412678, rhbz#2412758");

  script_tag(name:"affected", value:"'cri-o1.34' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.34", rpm:"cri-o1.34~1.34.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.34-debuginfo", rpm:"cri-o1.34-debuginfo~1.34.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.34-debugsource", rpm:"cri-o1.34-debugsource~1.34.2~1.fc43", rls:"FC43"))) {
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

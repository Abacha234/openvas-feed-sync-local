# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.37970906978");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910");
  script_tag(name:"creation_date", value:"2025-10-13 04:05:45 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-37970906a8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-37970906a8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-37970906a8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333357");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398407");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398662");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399064");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399338");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.32' package(s) announced via the FEDORA-2025-37970906a8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release 1.32.9
- Resolves: rhbz#2333357, rhbz#2398407, rhbz#2398662, rhbz#2399064,
 rhbz#2399338
- Upstream fix");

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

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32", rpm:"cri-o1.32~1.32.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32-debuginfo", rpm:"cri-o1.32-debuginfo~1.32.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.32-debugsource", rpm:"cri-o1.32-debugsource~1.32.9~1.fc42", rls:"FC42"))) {
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

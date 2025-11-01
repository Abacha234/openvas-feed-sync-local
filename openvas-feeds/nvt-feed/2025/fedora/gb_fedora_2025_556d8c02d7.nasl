# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.556100899021007");
  script_cve_id("CVE-2024-40635", "CVE-2025-22870", "CVE-2025-27144");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 15:09:09 +0000 (Tue, 23 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-556d8c02d7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-556d8c02d7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-556d8c02d7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347476");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352147");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2353096");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cri-o1.31' package(s) announced via the FEDORA-2025-556d8c02d7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for cri-o1.31-1.31.7-1.fc43.

##### **Changelog**

```
* Wed Apr 2 2025 Bradley G Smith <bradley.g.smith@gmail.com> - 1.31.7-1
- Update to release v1.31.7
- Resolves FTBFS due to changes in license detector
- Upstream fix
* Fri Mar 21 2025 Bradley G Smith <bradley.g.smith@gmail.com> - 1.31.6-2
- Resolve CVE-2024-40635 and CVE-2025-22870 and CVE-2025-27144
- Resolves rhbz#2352147, rhbz#2353096, rhbz#2347476
- Update vendored go modules: golang.org/x/net v0.34.0 to
 v0.36.0 github.com/containerd/containerd v1.7.24 to v1.7.27
 github.com/go-jose/go-jose/v4 v4.0.2 to v4.0.5

```");

  script_tag(name:"affected", value:"'cri-o1.31' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.31", rpm:"cri-o1.31~1.31.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.31-debuginfo", rpm:"cri-o1.31-debuginfo~1.31.7~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cri-o1.31-debugsource", rpm:"cri-o1.31-debugsource~1.31.7~1.fc43", rls:"FC43"))) {
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

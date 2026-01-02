# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9991029101100102688");
  script_cve_id("CVE-2024-25621");
  script_tag(name:"creation_date", value:"2025-12-26 04:19:34 +0000 (Fri, 26 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-31 02:29:30 +0000 (Wed, 31 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-9cf9edf688)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9cf9edf688");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9cf9edf688");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419004");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419427");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-buildkit' package(s) announced via the FEDORA-2025-9cf9edf688 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v0.26.3
- Resolves CVE-2024-25621: rhbz#2419004, rhbz#2419033, rhbz#2419427
- Upstream fix");

  script_tag(name:"affected", value:"'docker-buildkit' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit", rpm:"docker-buildkit~0.26.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit-debuginfo", rpm:"docker-buildkit-debuginfo~0.26.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit-debugsource", rpm:"docker-buildkit-debugsource~0.26.3~1.fc42", rls:"FC42"))) {
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

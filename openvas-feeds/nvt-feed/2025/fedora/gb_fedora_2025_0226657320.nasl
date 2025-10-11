# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.0226657320");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910");
  script_tag(name:"creation_date", value:"2025-10-10 04:05:56 +0000 (Fri, 10 Oct 2025)");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-0226657320)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-0226657320");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-0226657320");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398424");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398678");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399081");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399354");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-buildkit' package(s) announced via the FEDORA-2025-0226657320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v0.25.0
- Resolves: rhbz#2399354, rhbz#2399081, rhbz#2398678, rhbz#2398424
- Upstream feature additions and fixes");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit", rpm:"docker-buildkit~0.25.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit-debuginfo", rpm:"docker-buildkit-debuginfo~0.25.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildkit-debugsource", rpm:"docker-buildkit-debugsource~0.25.0~1.fc42", rls:"FC42"))) {
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

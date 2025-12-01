# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.04991021391011012");
  script_cve_id("CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-04cf139ee2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-04cf139ee2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-04cf139ee2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407881");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408158");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409066");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409350");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409628");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410014");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410579");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410946");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412381");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412530");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412682");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2413270");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-buildx' package(s) announced via the FEDORA-2025-04cf139ee2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v0.30.1
- Upstream fix

----

- Update to release v0.30.0
- Resolves: rhbz#2413270
- Resolves: rhbz#2407614, rhbz#2407881, rhbz#2408158, rhbz#2409066
- Resolves: rhbz#2409350, rhbz#2409628, rhbz#2410014, rhbz#2410300
- Resolves: rhbz#2410579, rhbz#2410946, rhbz#2411477, rhbz#2412381
- Resolves: rhbz#2412530, rhbz#2412682, rhbz#2412762
- Upstream new features and fixes");

  script_tag(name:"affected", value:"'docker-buildx' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx", rpm:"docker-buildx~0.30.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx-debuginfo", rpm:"docker-buildx-debuginfo~0.30.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx-debugsource", rpm:"docker-buildx-debugsource~0.30.1~1.fc42", rls:"FC42"))) {
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

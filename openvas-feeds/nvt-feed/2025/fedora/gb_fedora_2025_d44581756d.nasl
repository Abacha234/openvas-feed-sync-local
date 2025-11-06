# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10044581756100");
  script_tag(name:"creation_date", value:"2025-11-05 04:06:44 +0000 (Wed, 05 Nov 2025)");
  script_version("2025-11-05T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-11-05 05:40:07 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-d44581756d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d44581756d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d44581756d");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnbd' package(s) announced via the FEDORA-2025-d44581756d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream development version 1.23.10

----

New upstream development version 1.23.9");

  script_tag(name:"affected", value:"'libnbd' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnbd", rpm:"libnbd~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnbd-bash-completion", rpm:"libnbd-bash-completion~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnbd-debuginfo", rpm:"libnbd-debuginfo~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnbd-debugsource", rpm:"libnbd-debugsource~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnbd-devel", rpm:"libnbd-devel~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdfuse", rpm:"nbdfuse~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdfuse-debuginfo", rpm:"nbdfuse-debuginfo~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdublk", rpm:"nbdublk~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nbdublk-debuginfo", rpm:"nbdublk-debuginfo~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libnbd", rpm:"ocaml-libnbd~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libnbd-debuginfo", rpm:"ocaml-libnbd-debuginfo~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-libnbd-devel", rpm:"ocaml-libnbd-devel~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libnbd", rpm:"python3-libnbd~1.23.10~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libnbd-debuginfo", rpm:"python3-libnbd-debuginfo~1.23.10~1.fc43", rls:"FC43"))) {
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

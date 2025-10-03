# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.298599691021021016");
  script_cve_id("CVE-2025-59431");
  script_tag(name:"creation_date", value:"2025-10-02 04:05:15 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-2b5c69ffe6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2b5c69ffe6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2b5c69ffe6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2397021");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2397022");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mapserver' package(s) announced via the FEDORA-2025-2b5c69ffe6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to mapserver-8.4.1, fixes CVE-2025-59431.");

  script_tag(name:"affected", value:"'mapserver' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mapserver", rpm:"mapserver~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-debuginfo", rpm:"mapserver-debuginfo~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-debugsource", rpm:"mapserver-debugsource~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-devel", rpm:"mapserver-devel~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-java", rpm:"mapserver-java~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-libs", rpm:"mapserver-libs~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-libs-debuginfo", rpm:"mapserver-libs-debuginfo~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-perl", rpm:"mapserver-perl~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mapserver-ruby", rpm:"mapserver-ruby~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mapserver", rpm:"php-mapserver~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mapserver-debuginfo", rpm:"php-mapserver-debuginfo~8.4.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mapserver", rpm:"python3-mapserver~8.4.1~1.fc41", rls:"FC41"))) {
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

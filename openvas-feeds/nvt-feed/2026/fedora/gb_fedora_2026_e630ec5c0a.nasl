# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10163010199599097");
  script_cve_id("CVE-2025-68972", "CVE-2025-68973");
  script_tag(name:"creation_date", value:"2026-01-06 04:20:32 +0000 (Tue, 06 Jan 2026)");
  script_version("2026-01-06T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-06 05:47:51 +0000 (Tue, 06 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-e630ec5c0a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-e630ec5c0a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-e630ec5c0a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2425718");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2425765");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2' package(s) announced via the FEDORA-2026-e630ec5c0a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release 2.4.9 fixing several vulnerabilities");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.4.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-debuginfo", rpm:"gnupg2-debuginfo~2.4.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-debugsource", rpm:"gnupg2-debugsource~2.4.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-smime", rpm:"gnupg2-smime~2.4.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-smime-debuginfo", rpm:"gnupg2-smime-debuginfo~2.4.9~1.fc42", rls:"FC42"))) {
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

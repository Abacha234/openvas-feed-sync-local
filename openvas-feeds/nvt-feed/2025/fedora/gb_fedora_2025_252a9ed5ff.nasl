# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.2529791011005102102");
  script_cve_id("CVE-2025-46646");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-252a9ed5ff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-252a9ed5ff");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-252a9ed5ff");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362446");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362640");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362935");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the FEDORA-2025-252a9ed5ff advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for ghostscript-10.05.1-1.fc43.

##### **Changelog**

```
* Mon May 19 2025 Zdenek Dohnal <zdohnal@redhat.com> - 10.05.1-1
- 10.05.1, security fix for CVE-2025-46646 (fedora#2362935, fedora#2362446, fedora#2362640)

```");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk-debuginfo", rpm:"ghostscript-gtk-debuginfo~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-dvipdf", rpm:"ghostscript-tools-dvipdf~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-fonts", rpm:"ghostscript-tools-fonts~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-printing", rpm:"ghostscript-tools-printing~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs", rpm:"libgs~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-debuginfo", rpm:"libgs-debuginfo~10.05.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.05.1~1.fc43", rls:"FC43"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.589909897989742");
  script_cve_id("CVE-2024-55456", "CVE-2024-57719", "CVE-2024-57720", "CVE-2024-57721", "CVE-2024-57722", "CVE-2024-57723", "CVE-2024-57724");
  script_tag(name:"creation_date", value:"2025-12-10 04:15:05 +0000 (Wed, 10 Dec 2025)");
  script_version("2025-12-10T05:45:47+0000");
  script_tag(name:"last_modification", value:"2025-12-10 05:45:47 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-58c0baba42)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-58c0baba42");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-58c0baba42");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295891");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2341675");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343567");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400407");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imhex, lunasvg' package(s) announced via the FEDORA-2025-58c0baba42 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Unbundle `plutovg` from `lunasvg`, this avoids [shipping a duplicate library with conflicting files]([link moved to references]).
- Update `lunasvg` to consume the `plutovg` version already available in the repositories and to fix various CVEs.
- Rebuild `imhex` for the updated `lunasvg`.");

  script_tag(name:"affected", value:"'imhex, lunasvg' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"imhex", rpm:"imhex~1.37.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imhex-debuginfo", rpm:"imhex-debuginfo~1.37.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imhex-debugsource", rpm:"imhex-debugsource~1.37.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imhex-devel", rpm:"imhex-devel~1.37.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imhex-patterns", rpm:"imhex-patterns~1.37.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lunasvg", rpm:"lunasvg~3.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lunasvg-debuginfo", rpm:"lunasvg-debuginfo~3.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lunasvg-debugsource", rpm:"lunasvg-debugsource~3.5.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lunasvg-devel", rpm:"lunasvg-devel~3.5.0~1.fc43", rls:"FC43"))) {
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

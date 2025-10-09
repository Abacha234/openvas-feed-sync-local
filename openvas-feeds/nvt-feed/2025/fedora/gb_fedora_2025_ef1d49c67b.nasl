# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.101102110049996798");
  script_cve_id("CVE-2025-51591");
  script_tag(name:"creation_date", value:"2025-10-08 04:05:53 +0000 (Wed, 08 Oct 2025)");
  script_version("2025-10-08T05:38:55+0000");
  script_tag(name:"last_modification", value:"2025-10-08 05:38:55 +0000 (Wed, 08 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-ef1d49c67b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ef1d49c67b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ef1d49c67b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379955");
  script_xref(name:"URL", value:"https://github.com/jgm/pandoc/issues/9820");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pandoc, pandoc-cli' package(s) announced via the FEDORA-2025-ef1d49c67b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pandoc-cli:

- enable pandoc server (semantically safe) with pandoc-server-0.1.0.5

pandoc:

- apply upstream patch to avoid error with ConTeXt (#2365309)
 [link moved to references]");

  script_tag(name:"affected", value:"'pandoc, pandoc-cli' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc", rpm:"ghc-citeproc~0.8.1.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-devel", rpm:"ghc-citeproc-devel~0.8.1.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-doc", rpm:"ghc-citeproc-doc~0.8.1.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-prof", rpm:"ghc-citeproc-prof~0.8.1.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark", rpm:"ghc-commonmark~0.2.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-devel", rpm:"ghc-commonmark-devel~0.2.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-doc", rpm:"ghc-commonmark-doc~0.2.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions", rpm:"ghc-commonmark-extensions~0.2.5.5~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-devel", rpm:"ghc-commonmark-extensions-devel~0.2.5.5~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-doc", rpm:"ghc-commonmark-extensions-doc~0.2.5.5~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-prof", rpm:"ghc-commonmark-extensions-prof~0.2.5.5~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc", rpm:"ghc-commonmark-pandoc~0.2.2.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-devel", rpm:"ghc-commonmark-pandoc-devel~0.2.2.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-doc", rpm:"ghc-commonmark-pandoc-doc~0.2.2.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-prof", rpm:"ghc-commonmark-pandoc-prof~0.2.2.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-prof", rpm:"ghc-commonmark-prof~0.2.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits", rpm:"ghc-digits~0.3.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-devel", rpm:"ghc-digits-devel~0.3.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-doc", rpm:"ghc-digits-doc~0.3.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-prof", rpm:"ghc-digits-prof~0.3.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables", rpm:"ghc-gridtables~0.1.0.0~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-devel", rpm:"ghc-gridtables-devel~0.1.0.0~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-doc", rpm:"ghc-gridtables-doc~0.1.0.0~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-prof", rpm:"ghc-gridtables-prof~0.1.0.0~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli", rpm:"ghc-hslua-cli~1.4.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-devel", rpm:"ghc-hslua-cli-devel~1.4.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-doc", rpm:"ghc-hslua-cli-doc~1.4.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-prof", rpm:"ghc-hslua-cli-prof~1.4.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list", rpm:"ghc-hslua-list~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-devel", rpm:"ghc-hslua-list-devel~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-doc", rpm:"ghc-hslua-list-doc~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-prof", rpm:"ghc-hslua-list-prof~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout", rpm:"ghc-hslua-module-doclayout~1.1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-devel", rpm:"ghc-hslua-module-doclayout-devel~1.1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-doc", rpm:"ghc-hslua-module-doclayout-doc~1.1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-prof", rpm:"ghc-hslua-module-doclayout-prof~1.1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path", rpm:"ghc-hslua-module-path~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-devel", rpm:"ghc-hslua-module-path-devel~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-doc", rpm:"ghc-hslua-module-path-doc~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-prof", rpm:"ghc-hslua-module-path-prof~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system", rpm:"ghc-hslua-module-system~1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-devel", rpm:"ghc-hslua-module-system-devel~1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-doc", rpm:"ghc-hslua-module-system-doc~1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-prof", rpm:"ghc-hslua-module-system-prof~1.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version", rpm:"ghc-hslua-module-version~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-devel", rpm:"ghc-hslua-module-version-devel~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-doc", rpm:"ghc-hslua-module-version-doc~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-prof", rpm:"ghc-hslua-module-version-prof~1.1.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip", rpm:"ghc-hslua-module-zip~1.1.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-devel", rpm:"ghc-hslua-module-zip-devel~1.1.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-doc", rpm:"ghc-hslua-module-zip-doc~1.1.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-prof", rpm:"ghc-hslua-module-zip-prof~1.1.3~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl", rpm:"ghc-hslua-repl~0.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-devel", rpm:"ghc-hslua-repl-devel~0.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-doc", rpm:"ghc-hslua-repl-doc~0.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-prof", rpm:"ghc-hslua-repl-prof~0.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb", rpm:"ghc-ipynb~0.2~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-devel", rpm:"ghc-ipynb-devel~0.2~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-doc", rpm:"ghc-ipynb-doc~0.2~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-prof", rpm:"ghc-ipynb-prof~0.2~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup", rpm:"ghc-jira-wiki-markup~1.5.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-devel", rpm:"ghc-jira-wiki-markup-devel~1.5.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-doc", rpm:"ghc-jira-wiki-markup-doc~1.5.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-prof", rpm:"ghc-jira-wiki-markup-prof~1.5.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg", rpm:"ghc-lpeg~1.0.4~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-devel", rpm:"ghc-lpeg-devel~1.0.4~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-doc", rpm:"ghc-lpeg-doc~1.0.4~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-prof", rpm:"ghc-lpeg-prof~1.0.4~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers", rpm:"ghc-ordered-containers~0.2.4~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-devel", rpm:"ghc-ordered-containers-devel~0.2.4~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-doc", rpm:"ghc-ordered-containers-doc~0.2.4~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-prof", rpm:"ghc-ordered-containers-prof~0.2.4~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc", rpm:"ghc-pandoc~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-devel", rpm:"ghc-pandoc-devel~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-doc", rpm:"ghc-pandoc-doc~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine", rpm:"ghc-pandoc-lua-engine~0.2.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-devel", rpm:"ghc-pandoc-lua-engine-devel~0.2.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-doc", rpm:"ghc-pandoc-lua-engine-doc~0.2.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-prof", rpm:"ghc-pandoc-lua-engine-prof~0.2.1.2~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal", rpm:"ghc-pandoc-lua-marshal~0.2.7.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-devel", rpm:"ghc-pandoc-lua-marshal-devel~0.2.7.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-doc", rpm:"ghc-pandoc-lua-marshal-doc~0.2.7.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-prof", rpm:"ghc-pandoc-lua-marshal-prof~0.2.7.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-prof", rpm:"ghc-pandoc-prof~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-server", rpm:"ghc-pandoc-server~0.1.0.5~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-server-devel", rpm:"ghc-pandoc-server-devel~0.1.0.5~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-server-doc", rpm:"ghc-pandoc-server-doc~0.1.0.5~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-server-prof", rpm:"ghc-pandoc-server-prof~0.1.0.5~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst", rpm:"ghc-typst~0.5.0.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-devel", rpm:"ghc-typst-devel~0.5.0.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-doc", rpm:"ghc-typst-doc~0.5.0.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-prof", rpm:"ghc-typst-prof~0.5.0.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation", rpm:"ghc-unicode-collation~0.1.3.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-devel", rpm:"ghc-unicode-collation-devel~0.1.3.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-doc", rpm:"ghc-unicode-collation-doc~0.1.3.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-prof", rpm:"ghc-unicode-collation-prof~0.1.3.6~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc", rpm:"pandoc~3.1.11.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc", rpm:"pandoc~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-cli", rpm:"pandoc-cli~3.1.11.1~34.1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-common", rpm:"pandoc-common~3.1.11.1~34.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-pdf", rpm:"pandoc-pdf~3.1.11.1~34.1.fc41", rls:"FC41"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.7995986973989998");
  script_cve_id("CVE-2024-2971", "CVE-2024-3247", "CVE-2024-3248", "CVE-2024-3900", "CVE-2024-4141", "CVE-2024-4568", "CVE-2024-4976", "CVE-2024-7866", "CVE-2024-7867", "CVE-2024-7868", "CVE-2025-11896", "CVE-2025-2574", "CVE-2025-3154");
  script_tag(name:"creation_date", value:"2025-12-05 04:12:57 +0000 (Fri, 05 Dec 2025)");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 12:40:01 +0000 (Wed, 11 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-7c5b6a3bcb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-7c5b6a3bcb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-7c5b6a3bcb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271913");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272853");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272856");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275829");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277032");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279473");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305301");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305302");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354014");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357056");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-base, xpdf' package(s) announced via the FEDORA-2025-7c5b6a3bcb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 4.06. Lots of bugfixes, but notably, security fixes for the following CVEs:

CVE-2024-2971
CVE-2024-3247
CVE-2024-3248
CVE-2024-3900
CVE-2024-4141
CVE-2024-4568
CVE-2024-4976
CVE-2024-7866
CVE-2024-7867
CVE-2024-7868
CVE-2025-2574
CVE-2025-3154
CVE-2025-11896");

  script_tag(name:"affected", value:"'texlive-base, xpdf' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"texlive-a2ping", rpm:"texlive-a2ping~svn52964~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-accfonts", rpm:"texlive-accfonts~svn18835~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-adhocfilelist", rpm:"texlive-adhocfilelist~svn29349~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-debuginfo", rpm:"texlive-afm2pl-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl", rpm:"texlive-afm2pl~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-albatross", rpm:"texlive-albatross~svn65647~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-debuginfo", rpm:"texlive-aleph-debuginfo~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph", rpm:"texlive-aleph~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-amstex", rpm:"texlive-amstex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-arara", rpm:"texlive-arara~svn63760~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-attachfile2", rpm:"texlive-attachfile2~svn57959~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-authorindex", rpm:"texlive-authorindex~svn51757~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-debuginfo", rpm:"texlive-autosp-debuginfo~svn58211~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp", rpm:"texlive-autosp~svn58211~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2-debuginfo", rpm:"texlive-axodraw2-debuginfo~svn58155~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-axodraw2", rpm:"texlive-axodraw2~svn58155~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-base", rpm:"texlive-base~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-base-debuginfo", rpm:"texlive-base-debuginfo~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-base-debugsource", rpm:"texlive-base-debugsource~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bib2gls", rpm:"texlive-bib2gls~svn65104~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibcop", rpm:"texlive-bibcop~svn65816~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibexport", rpm:"texlive-bibexport~svn50677~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-debuginfo", rpm:"texlive-bibtex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex", rpm:"texlive-bibtex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-debuginfo", rpm:"texlive-bibtex8-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8", rpm:"texlive-bibtex8~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-debuginfo", rpm:"texlive-bibtexu-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu", rpm:"texlive-bibtexu~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bundledoc", rpm:"texlive-bundledoc~svn64620~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cachepic", rpm:"texlive-cachepic~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checkcites", rpm:"texlive-checkcites~svn64155~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checklistings", rpm:"texlive-checklistings~svn38300~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chklref", rpm:"texlive-chklref~svn52649~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-debuginfo", rpm:"texlive-chktex-debuginfo~svn64797~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex", rpm:"texlive-chktex~svn64797~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-citation-style-language", rpm:"texlive-citation-style-language~svn65878~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-debuginfo", rpm:"texlive-cjkutils-debuginfo~svn60833~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils", rpm:"texlive-cjkutils~svn60833~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-clojure-pamphlet", rpm:"texlive-clojure-pamphlet~svn60981~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cluttex", rpm:"texlive-cluttex~svn60964~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context-doc", rpm:"texlive-context-doc~svn66546~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context", rpm:"texlive-context~svn66546~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-convbkmk", rpm:"texlive-convbkmk~svn49252~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-crossrefware", rpm:"texlive-crossrefware~svn64754~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cslatex", rpm:"texlive-cslatex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-csplain", rpm:"texlive-csplain~svn62771~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctan-o-mat", rpm:"texlive-ctan-o-mat~svn51578~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanbib", rpm:"texlive-ctanbib~svn66068~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanify", rpm:"texlive-ctanify~svn44129~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanupload", rpm:"texlive-ctanupload~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-debuginfo", rpm:"texlive-ctie-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie", rpm:"texlive-ctie~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-debuginfo", rpm:"texlive-cweb-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb", rpm:"texlive-cweb~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cyrillic", rpm:"texlive-cyrillic~svn63613~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-de-macro", rpm:"texlive-de-macro~svn61719~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-debuginfo", rpm:"texlive-detex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex", rpm:"texlive-detex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-diadia", rpm:"texlive-diadia~svn37656~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-digestif", rpm:"texlive-digestif~svn65223~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dosepsbin", rpm:"texlive-dosepsbin~svn29752~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-debuginfo", rpm:"texlive-dtl-debuginfo~svn62387~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl", rpm:"texlive-dtl~svn62387~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtxgen", rpm:"texlive-dtxgen~svn51663~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvi2tty-debuginfo", rpm:"texlive-dvi2tty-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvi2tty", rpm:"texlive-dvi2tty~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviasm", rpm:"texlive-dviasm~svn64430~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-debuginfo", rpm:"texlive-dvicopy-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy", rpm:"texlive-dvicopy~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-debuginfo", rpm:"texlive-dvidvi-debuginfo~svn65952~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi", rpm:"texlive-dvidvi~svn65952~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviinfox", rpm:"texlive-dviinfox~svn59216~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-debuginfo", rpm:"texlive-dviljk-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk", rpm:"texlive-dviljk~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util-debuginfo", rpm:"texlive-dviout-util-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviout-util", rpm:"texlive-dviout-util~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx", rpm:"texlive-dvipdfmx~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-debuginfo", rpm:"texlive-dvipng-debuginfo~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng", rpm:"texlive-dvipng~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-debuginfo", rpm:"texlive-dvipos-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos", rpm:"texlive-dvipos~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-debuginfo", rpm:"texlive-dvips-debuginfo~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips", rpm:"texlive-dvips~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-debuginfo", rpm:"texlive-dvisvgm-debuginfo~svn66532~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm", rpm:"texlive-dvisvgm~svn66532~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ebong", rpm:"texlive-ebong~svn55475~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-eplain", rpm:"texlive-eplain~svn64721~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epspdf", rpm:"texlive-epspdf~svn66115~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epstopdf", rpm:"texlive-epstopdf~svn66461~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-exceltex", rpm:"texlive-exceltex~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fig4latex", rpm:"texlive-fig4latex~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-findhyph", rpm:"texlive-findhyph~svn47444~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontinst", rpm:"texlive-fontinst~svn62517~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontools", rpm:"texlive-fontools~svn65706~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-debuginfo", rpm:"texlive-fontware-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware", rpm:"texlive-fontware~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fragmaster", rpm:"texlive-fragmaster~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-getmap", rpm:"texlive-getmap~svn50589~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-git-latexdiff", rpm:"texlive-git-latexdiff~svn54732~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-glossaries", rpm:"texlive-glossaries~svn64919~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-glyphlist", rpm:"texlive-glyphlist~svn54074~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-debuginfo", rpm:"texlive-gregoriotex-debuginfo~svn58331~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex", rpm:"texlive-gregoriotex~svn58331~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-debuginfo", rpm:"texlive-gsftopk-debuginfo~svn52851~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk", rpm:"texlive-gsftopk~svn52851~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-hitex-debuginfo", rpm:"texlive-hitex-debuginfo~svn65883~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-hitex", rpm:"texlive-hitex~svn65883~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-hyperxmp", rpm:"texlive-hyperxmp~svn65980~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-installfont", rpm:"texlive-installfont~svn31205~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jadetex", rpm:"texlive-jadetex~svn63654~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jfmutil", rpm:"texlive-jfmutil~svn60987~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ketcindy", rpm:"texlive-ketcindy~svn58661~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kotex-utils", rpm:"texlive-kotex-utils~svn38727~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-debuginfo", rpm:"texlive-kpathsea-debuginfo~svn66209~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea", rpm:"texlive-kpathsea~svn66209~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-l3build", rpm:"texlive-l3build~svn66471~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-debuginfo", rpm:"texlive-lacheck-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck", rpm:"texlive-lacheck~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-git-log", rpm:"texlive-latex-git-log~svn54010~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-papersize", rpm:"texlive-latex-papersize~svn53131~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex", rpm:"texlive-latex~svn65161~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2man", rpm:"texlive-latex2man~svn64477~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2nemeth", rpm:"texlive-latex2nemeth~svn65269~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexdiff", rpm:"texlive-latexdiff~svn64980~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexfileversion", rpm:"texlive-latexfileversion~svn29349~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexindent", rpm:"texlive-latexindent~svn65937~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexpand", rpm:"texlive-latexpand~svn66226~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-debuginfo", rpm:"texlive-lcdftypetools-debuginfo~svn52851~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools", rpm:"texlive-lcdftypetools~svn52851~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lib", rpm:"texlive-lib~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lib-debuginfo", rpm:"texlive-lib-debuginfo~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lib-devel", rpm:"texlive-lib-devel~20230311~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-light-latex-make", rpm:"texlive-light-latex-make~svn66473~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lilyglyphs", rpm:"texlive-lilyglyphs~svn56473~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listbib", rpm:"texlive-listbib~svn29349~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listings-ext", rpm:"texlive-listings-ext~svn29349~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lollipop", rpm:"texlive-lollipop~svn45678~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltxfileinfo", rpm:"texlive-ltxfileinfo~svn38663~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltximg", rpm:"texlive-ltximg~svn59335~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luafindfont", rpm:"texlive-luafindfont~svn64936~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex-debuginfo", rpm:"texlive-luahbtex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luahbtex", rpm:"texlive-luahbtex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex-debuginfo", rpm:"texlive-luajittex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luajittex", rpm:"texlive-luajittex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luaotfload", rpm:"texlive-luaotfload~svn64616~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-debuginfo", rpm:"texlive-luatex-debuginfo~svn66967~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex", rpm:"texlive-luatex~svn66967~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lwarp", rpm:"texlive-lwarp~svn66259~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lyluatex", rpm:"texlive-lyluatex~svn66278~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-debuginfo", rpm:"texlive-m-tx-debuginfo~svn64182~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx", rpm:"texlive-m-tx~svn64182~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-make4ht", rpm:"texlive-make4ht~svn66130~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makedtx", rpm:"texlive-makedtx~svn46702~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-debuginfo", rpm:"texlive-makeindex-debuginfo~svn62517~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex", rpm:"texlive-makeindex~svn62517~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-match_parens", rpm:"texlive-match_parens~svn36270~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mathspic", rpm:"texlive-mathspic~svn31957~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-debuginfo", rpm:"texlive-metafont-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont", rpm:"texlive-metafont~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-debuginfo", rpm:"texlive-metapost-debuginfo~svn66264~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost", rpm:"texlive-metapost~svn66264~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mex", rpm:"texlive-mex~svn58661~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mf2pt1", rpm:"texlive-mf2pt1~svn61217~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-debuginfo", rpm:"texlive-mflua-debuginfo~svn62774~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua", rpm:"texlive-mflua~svn62774~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-debuginfo", rpm:"texlive-mfware-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware", rpm:"texlive-mfware~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkgrkindex", rpm:"texlive-mkgrkindex~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkjobtexmf", rpm:"texlive-mkjobtexmf~svn29725~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkpic", rpm:"texlive-mkpic~svn33700~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mltex", rpm:"texlive-mltex~svn62145~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mptopdf", rpm:"texlive-mptopdf~svn65952~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-multibibliography", rpm:"texlive-multibibliography~svn30939~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtex", rpm:"texlive-musixtex~svn65519~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-debuginfo", rpm:"texlive-musixtnt-debuginfo~svn40307~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt", rpm:"texlive-musixtnt~svn40307~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-oberdiek", rpm:"texlive-oberdiek~svn65521~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-debuginfo", rpm:"texlive-omegaware-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware", rpm:"texlive-omegaware~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-optex", rpm:"texlive-optex~svn66513~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-optexcount", rpm:"texlive-optexcount~svn59817~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pagelayout", rpm:"texlive-pagelayout~svn66392~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-debuginfo", rpm:"texlive-patgen-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen", rpm:"texlive-patgen~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pax", rpm:"texlive-pax~svn63509~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfbook2", rpm:"texlive-pdfbook2~svn53521~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfcrop", rpm:"texlive-pdfcrop~svn55435~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfjam", rpm:"texlive-pdfjam~svn56991~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdflatexpicscale", rpm:"texlive-pdflatexpicscale~svn46617~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-debuginfo", rpm:"texlive-pdftex-debuginfo~svn66243~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-quiet", rpm:"texlive-pdftex-quiet~svn49169~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex", rpm:"texlive-pdftex~svn66243~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc-debuginfo", rpm:"texlive-pdftosrc-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftosrc", rpm:"texlive-pdftosrc~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfxup", rpm:"texlive-pdfxup~svn59001~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pedigree-perl", rpm:"texlive-pedigree-perl~svn64227~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-perltex", rpm:"texlive-perltex~svn52162~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-petri-nets", rpm:"texlive-petri-nets~svn39165~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pfarrei", rpm:"texlive-pfarrei~svn31934~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-helper", rpm:"texlive-pkfix-helper~svn56061~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix", rpm:"texlive-pkfix~svn26032~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-debuginfo", rpm:"texlive-pmx-debuginfo~svn65926~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx", rpm:"texlive-pmx~svn65926~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmxchords", rpm:"texlive-pmxchords~svn39249~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps-debuginfo", rpm:"texlive-ps2eps-debuginfo~svn62856~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2eps", rpm:"texlive-ps2eps~svn62856~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-debuginfo", rpm:"texlive-ps2pk-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk", rpm:"texlive-ps2pk~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst-pdf", rpm:"texlive-pst-pdf~svn56622~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst2pdf", rpm:"texlive-pst2pdf~svn56172~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-psutils-debuginfo", rpm:"texlive-psutils-debuginfo~svn61719~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-psutils", rpm:"texlive-psutils~svn61719~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-debuginfo", rpm:"texlive-ptex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-fontmaps", rpm:"texlive-ptex-fontmaps~svn65953~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex", rpm:"texlive-ptex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex2pdf", rpm:"texlive-ptex2pdf~svn65953~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-purifyeps", rpm:"texlive-purifyeps~svn29725~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pygmentex", rpm:"texlive-pygmentex~svn64131~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pythontex", rpm:"texlive-pythontex~svn59514~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-rubik", rpm:"texlive-rubik~svn46791~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-debuginfo", rpm:"texlive-seetexk-debuginfo~svn57972~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk", rpm:"texlive-seetexk~svn57972~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-spix", rpm:"texlive-spix~svn65050~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-splitindex", rpm:"texlive-splitindex~svn39766~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-srcredact", rpm:"texlive-srcredact~svn38710~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-sty2dtx", rpm:"texlive-sty2dtx~svn64967~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-svn-multi", rpm:"texlive-svn-multi~svn64967~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-debuginfo", rpm:"texlive-synctex-debuginfo~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex", rpm:"texlive-synctex~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-debuginfo", rpm:"texlive-tex-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex", rpm:"texlive-tex~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ebook", rpm:"texlive-tex4ebook~svn66332~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-debuginfo", rpm:"texlive-tex4ht-debuginfo~svn66530~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht", rpm:"texlive-tex4ht~svn66530~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texaccents", rpm:"texlive-texaccents~svn64447~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texcount", rpm:"texlive-texcount~svn49013~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdef", rpm:"texlive-texdef~svn64967~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdiff", rpm:"texlive-texdiff~svn29752~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdirflatten", rpm:"texlive-texdirflatten~svn55064~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoc", rpm:"texlive-texdoc~svn66227~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoctk", rpm:"texlive-texdoctk~svn62186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texfot", rpm:"texlive-texfot~svn65545~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlive-en", rpm:"texlive-texlive-en~svn66572~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlive-scripts-extra", rpm:"texlive-texlive-scripts-extra~svn62517~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlive-scripts", rpm:"texlive-texlive-scripts~svn66584~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlive.infra", rpm:"texlive-texlive.infra~svn66512~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texliveonfly", rpm:"texlive-texliveonfly~svn55777~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texloganalyser", rpm:"texlive-texloganalyser~svn54526~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlogfilter", rpm:"texlive-texlogfilter~svn62792~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlogsieve", rpm:"texlive-texlogsieve~svn64301~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texosquery", rpm:"texlive-texosquery~svn53676~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texplate", rpm:"texlive-texplate~svn61719~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texsis", rpm:"texlive-texsis~svn45678~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-debuginfo", rpm:"texlive-texware-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware", rpm:"texlive-texware~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-thumbpdf", rpm:"texlive-thumbpdf~svn62518~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-debuginfo", rpm:"texlive-tie-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie", rpm:"texlive-tie~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tikztosvg", rpm:"texlive-tikztosvg~svn60289~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tpic2pdftex", rpm:"texlive-tpic2pdftex~svn52851~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-debuginfo", rpm:"texlive-ttfutils-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils", rpm:"texlive-ttfutils~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-typeoutfileinfo", rpm:"texlive-typeoutfileinfo~svn29349~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ulqda", rpm:"texlive-ulqda~svn26313~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-upmendex-debuginfo", rpm:"texlive-upmendex-debuginfo~svn66381~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-upmendex", rpm:"texlive-upmendex~svn66381~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-debuginfo", rpm:"texlive-uptex-debuginfo~svn66381~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex", rpm:"texlive-uptex~svn66381~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-urlbst", rpm:"texlive-urlbst~svn65694~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-debuginfo", rpm:"texlive-velthuis-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis", rpm:"texlive-velthuis~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-debuginfo", rpm:"texlive-vlna-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna", rpm:"texlive-vlna~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vpe", rpm:"texlive-vpe~svn26039~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-debuginfo", rpm:"texlive-web-debuginfo~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web", rpm:"texlive-web~svn66186~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-webquiz", rpm:"texlive-webquiz~svn58808~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-wordcount", rpm:"texlive-wordcount~svn46165~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-debuginfo", rpm:"texlive-xdvi-debuginfo~svn62387~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi", rpm:"texlive-xdvi~svn62387~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-debuginfo", rpm:"texlive-xetex-debuginfo~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex", rpm:"texlive-xetex~svn66203~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xindex", rpm:"texlive-xindex~svn65597~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xindy-debuginfo", rpm:"texlive-xindy-debuginfo~svn65958~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xindy", rpm:"texlive-xindy~svn65958~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx-debuginfo", rpm:"texlive-xml2pmx-debuginfo~svn57972~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xml2pmx", rpm:"texlive-xml2pmx~svn57972~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xmltex", rpm:"texlive-xmltex~svn62145~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen-debuginfo", rpm:"texlive-xpdfopen-debuginfo~svn65952~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xpdfopen", rpm:"texlive-xpdfopen~svn65952~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-yplan", rpm:"texlive-yplan~svn34398~94.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~4.06~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-debuginfo", rpm:"xpdf-debuginfo~4.06~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-debugsource", rpm:"xpdf-debugsource~4.06~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-devel", rpm:"xpdf-devel~4.06~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-libs", rpm:"xpdf-libs~4.06~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-libs-debuginfo", rpm:"xpdf-libs-debuginfo~4.06~1.fc43", rls:"FC43"))) {
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

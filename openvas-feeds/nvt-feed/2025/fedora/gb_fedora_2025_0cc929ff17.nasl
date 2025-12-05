# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.0999992910210217");
  script_tag(name:"creation_date", value:"2025-12-04 04:12:22 +0000 (Thu, 04 Dec 2025)");
  script_version("2025-12-04T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-12-04 05:40:45 +0000 (Thu, 04 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-0cc929ff17)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-0cc929ff17");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-0cc929ff17");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400455");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gi-loadouts, kf6-kcoreaddons, kf6-kguiaddons, kf6-kjobwidgets, kf6-knotifications, kf6-kstatusnotifieritem, kf6-kunitconversion, kf6-kwidgetsaddons, kf6-kxmlgui, nanovna-saver, persepolis, python-ezdxf, python-pyside6, sigil, syncplay, torbrowser-launcher, ubertooth, usd' package(s) announced via the FEDORA-2025-0cc929ff17 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PySide6 6.10.1 update.

----

Pyside6 6.10.1 release.

----

Rebuilt with stb_image patched for two new security bugs.");

  script_tag(name:"affected", value:"'gi-loadouts, kf6-kcoreaddons, kf6-kguiaddons, kf6-kjobwidgets, kf6-knotifications, kf6-kstatusnotifieritem, kf6-kunitconversion, kf6-kwidgetsaddons, kf6-kxmlgui, nanovna-saver, persepolis, python-ezdxf, python-pyside6, sigil, syncplay, torbrowser-launcher, ubertooth, usd' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gi-loadouts", rpm:"gi-loadouts~0.1.10~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons", rpm:"kf6-kcoreaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons-debuginfo", rpm:"kf6-kcoreaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons-debugsource", rpm:"kf6-kcoreaddons-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons-devel", rpm:"kf6-kcoreaddons-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons-doc", rpm:"kf6-kcoreaddons-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kcoreaddons-html", rpm:"kf6-kcoreaddons-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons", rpm:"kf6-kguiaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons-debuginfo", rpm:"kf6-kguiaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons-debugsource", rpm:"kf6-kguiaddons-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons-devel", rpm:"kf6-kguiaddons-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons-doc", rpm:"kf6-kguiaddons-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kguiaddons-html", rpm:"kf6-kguiaddons-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets", rpm:"kf6-kjobwidgets~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets-debuginfo", rpm:"kf6-kjobwidgets-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets-debugsource", rpm:"kf6-kjobwidgets-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets-devel", rpm:"kf6-kjobwidgets-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets-doc", rpm:"kf6-kjobwidgets-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kjobwidgets-html", rpm:"kf6-kjobwidgets-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications", rpm:"kf6-knotifications~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications-debuginfo", rpm:"kf6-knotifications-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications-debugsource", rpm:"kf6-knotifications-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications-devel", rpm:"kf6-knotifications-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications-doc", rpm:"kf6-knotifications-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-knotifications-html", rpm:"kf6-knotifications-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem", rpm:"kf6-kstatusnotifieritem~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem-debuginfo", rpm:"kf6-kstatusnotifieritem-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem-debugsource", rpm:"kf6-kstatusnotifieritem-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem-devel", rpm:"kf6-kstatusnotifieritem-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem-doc", rpm:"kf6-kstatusnotifieritem-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kstatusnotifieritem-html", rpm:"kf6-kstatusnotifieritem-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion", rpm:"kf6-kunitconversion~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion-debuginfo", rpm:"kf6-kunitconversion-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion-debugsource", rpm:"kf6-kunitconversion-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion-devel", rpm:"kf6-kunitconversion-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion-doc", rpm:"kf6-kunitconversion-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kunitconversion-html", rpm:"kf6-kunitconversion-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons", rpm:"kf6-kwidgetsaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-debuginfo", rpm:"kf6-kwidgetsaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-debugsource", rpm:"kf6-kwidgetsaddons-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-devel", rpm:"kf6-kwidgetsaddons-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-devel-debuginfo", rpm:"kf6-kwidgetsaddons-devel-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-doc", rpm:"kf6-kwidgetsaddons-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kwidgetsaddons-html", rpm:"kf6-kwidgetsaddons-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui", rpm:"kf6-kxmlgui~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-debuginfo", rpm:"kf6-kxmlgui-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-debugsource", rpm:"kf6-kxmlgui-debugsource~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-devel", rpm:"kf6-kxmlgui-devel~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-devel-debuginfo", rpm:"kf6-kxmlgui-devel-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-doc", rpm:"kf6-kxmlgui-doc~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kf6-kxmlgui-html", rpm:"kf6-kxmlgui-html~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubertooth", rpm:"libubertooth~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libubertooth-debuginfo", rpm:"libubertooth-debuginfo~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nanovna-saver", rpm:"nanovna-saver~0.7.3~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"persepolis", rpm:"persepolis~5.1.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyside6-tools", rpm:"pyside6-tools~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pyside6-tools-debuginfo", rpm:"pyside6-tools-debuginfo~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-ezdxf", rpm:"python-ezdxf~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-ezdxf-debugsource", rpm:"python-ezdxf-debugsource~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-ezdxf-doc", rpm:"python-ezdxf-doc~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyside6", rpm:"python-pyside6~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyside6-debugsource", rpm:"python-pyside6-debugsource~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ezdxf+draw", rpm:"python3-ezdxf+draw~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ezdxf+draw5", rpm:"python3-ezdxf+draw5~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ezdxf", rpm:"python3-ezdxf~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ezdxf-debuginfo", rpm:"python3-ezdxf-debuginfo~1.4.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kcoreaddons", rpm:"python3-kf6-kcoreaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kcoreaddons-debuginfo", rpm:"python3-kf6-kcoreaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kguiaddons", rpm:"python3-kf6-kguiaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kguiaddons-debuginfo", rpm:"python3-kf6-kguiaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kjobwidgets", rpm:"python3-kf6-kjobwidgets~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kjobwidgets-debuginfo", rpm:"python3-kf6-kjobwidgets-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-knotifications", rpm:"python3-kf6-knotifications~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-knotifications-debuginfo", rpm:"python3-kf6-knotifications-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kstatusnotifieritem", rpm:"python3-kf6-kstatusnotifieritem~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kstatusnotifieritem-debuginfo", rpm:"python3-kf6-kstatusnotifieritem-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kunitconversion", rpm:"python3-kf6-kunitconversion~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kunitconversion-debuginfo", rpm:"python3-kf6-kunitconversion-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kwidgetsaddons", rpm:"python3-kf6-kwidgetsaddons~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kwidgetsaddons-debuginfo", rpm:"python3-kf6-kwidgetsaddons-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kxmlgui", rpm:"python3-kf6-kxmlgui~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-kf6-kxmlgui-debuginfo", rpm:"python3-kf6-kxmlgui-debuginfo~6.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside6", rpm:"python3-pyside6~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyside6-devel", rpm:"python3-pyside6-devel~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-shiboken6", rpm:"python3-shiboken6~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-shiboken6-devel", rpm:"python3-shiboken6-devel~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-shiboken6-devel-debuginfo", rpm:"python3-shiboken6-devel-debuginfo~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-usd", rpm:"python3-usd~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-usd-debuginfo", rpm:"python3-usd-debuginfo~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shiboken6", rpm:"shiboken6~6.10.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigil", rpm:"sigil~2.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigil-debuginfo", rpm:"sigil-debuginfo~2.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigil-debugsource", rpm:"sigil-debugsource~2.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigil-doc", rpm:"sigil-doc~2.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syncplay", rpm:"syncplay~1.7.4~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torbrowser-launcher", rpm:"torbrowser-launcher~0.3.9~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ubertooth", rpm:"ubertooth~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ubertooth-debuginfo", rpm:"ubertooth-debuginfo~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ubertooth-debugsource", rpm:"ubertooth-debugsource~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ubertooth-devel", rpm:"ubertooth-devel~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ubertooth-specan-ui", rpm:"ubertooth-specan-ui~2020.12.R1~24.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd", rpm:"usd~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd-debuginfo", rpm:"usd-debuginfo~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd-debugsource", rpm:"usd-debugsource~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd-devel", rpm:"usd-devel~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd-libs", rpm:"usd-libs~25.08~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"usd-libs-debuginfo", rpm:"usd-libs-debuginfo~25.08~11.fc43", rls:"FC43"))) {
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

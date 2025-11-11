# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10011261100473");
  script_tag(name:"creation_date", value:"2025-11-10 04:10:19 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-d11261d473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d11261d473");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d11261d473");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fcitx5, fcitx5-anthy, fcitx5-chewing, fcitx5-chinese-addons, fcitx5-configtool, fcitx5-hangul, fcitx5-kkc, fcitx5-libthai, fcitx5-m17n, fcitx5-qt, fcitx5-rime, fcitx5-sayura, fcitx5-skk, fcitx5-table-extra, fcitx5-unikey, fcitx5-zhuyin, libime' package(s) announced via the FEDORA-2025-d11261d473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fcitx5-5.1.16 update");

  script_tag(name:"affected", value:"'fcitx5, fcitx5-anthy, fcitx5-chewing, fcitx5-chinese-addons, fcitx5-configtool, fcitx5-hangul, fcitx5-kkc, fcitx5-libthai, fcitx5-m17n, fcitx5-qt, fcitx5-rime, fcitx5-sayura, fcitx5-skk, fcitx5-table-extra, fcitx5-unikey, fcitx5-zhuyin, libime' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"fcitx5", rpm:"fcitx5~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-anthy", rpm:"fcitx5-anthy~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-anthy-debuginfo", rpm:"fcitx5-anthy-debuginfo~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-anthy-debugsource", rpm:"fcitx5-anthy-debugsource~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-autostart", rpm:"fcitx5-autostart~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chewing", rpm:"fcitx5-chewing~5.1.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chewing-debuginfo", rpm:"fcitx5-chewing-debuginfo~5.1.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chewing-debugsource", rpm:"fcitx5-chewing-debugsource~5.1.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chinese-addons", rpm:"fcitx5-chinese-addons~5.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chinese-addons-data", rpm:"fcitx5-chinese-addons-data~5.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chinese-addons-debuginfo", rpm:"fcitx5-chinese-addons-debuginfo~5.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chinese-addons-debugsource", rpm:"fcitx5-chinese-addons-debugsource~5.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-chinese-addons-devel", rpm:"fcitx5-chinese-addons-devel~5.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-configtool", rpm:"fcitx5-configtool~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-configtool-debuginfo", rpm:"fcitx5-configtool-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-configtool-debugsource", rpm:"fcitx5-configtool-debugsource~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-data", rpm:"fcitx5-data~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-debuginfo", rpm:"fcitx5-debuginfo~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-debugsource", rpm:"fcitx5-debugsource~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-devel", rpm:"fcitx5-devel~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-hangul", rpm:"fcitx5-hangul~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-hangul-debuginfo", rpm:"fcitx5-hangul-debuginfo~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-hangul-debugsource", rpm:"fcitx5-hangul-debugsource~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-kkc", rpm:"fcitx5-kkc~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-kkc-debuginfo", rpm:"fcitx5-kkc-debuginfo~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-kkc-debugsource", rpm:"fcitx5-kkc-debugsource~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-libs", rpm:"fcitx5-libs~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-libs-debuginfo", rpm:"fcitx5-libs-debuginfo~5.1.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-libthai", rpm:"fcitx5-libthai~5.1.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-libthai-debuginfo", rpm:"fcitx5-libthai-debuginfo~5.1.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-libthai-debugsource", rpm:"fcitx5-libthai-debugsource~5.1.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-m17n", rpm:"fcitx5-m17n~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-m17n-debuginfo", rpm:"fcitx5-m17n-debuginfo~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-m17n-debugsource", rpm:"fcitx5-m17n-debugsource~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-migrator", rpm:"fcitx5-migrator~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-migrator-debuginfo", rpm:"fcitx5-migrator-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-migrator-devel", rpm:"fcitx5-migrator-devel~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt", rpm:"fcitx5-qt~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debuginfo", rpm:"fcitx5-qt-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-debugsource", rpm:"fcitx5-qt-debugsource~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-devel", rpm:"fcitx5-qt-devel~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets", rpm:"fcitx5-qt-libfcitx5qt5widgets~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt5widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt5widgets-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets", rpm:"fcitx5-qt-libfcitx5qt6widgets~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qt6widgets-debuginfo", rpm:"fcitx5-qt-libfcitx5qt6widgets-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus", rpm:"fcitx5-qt-libfcitx5qtdbus~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-libfcitx5qtdbus-debuginfo", rpm:"fcitx5-qt-libfcitx5qtdbus-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui", rpm:"fcitx5-qt-qt5gui~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt5gui-debuginfo", rpm:"fcitx5-qt-qt5gui-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui", rpm:"fcitx5-qt-qt6gui~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt-qt6gui-debuginfo", rpm:"fcitx5-qt-qt6gui-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5", rpm:"fcitx5-qt5~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt5-debuginfo", rpm:"fcitx5-qt5-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6", rpm:"fcitx5-qt6~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-qt6-debuginfo", rpm:"fcitx5-qt6-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-rime", rpm:"fcitx5-rime~5.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-rime-debuginfo", rpm:"fcitx5-rime-debuginfo~5.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-rime-debugsource", rpm:"fcitx5-rime-debugsource~5.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-sayura", rpm:"fcitx5-sayura~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-sayura-debuginfo", rpm:"fcitx5-sayura-debuginfo~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-sayura-debugsource", rpm:"fcitx5-sayura-debugsource~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-skk", rpm:"fcitx5-skk~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-skk-debuginfo", rpm:"fcitx5-skk-debuginfo~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-skk-debugsource", rpm:"fcitx5-skk-debugsource~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-table-extra", rpm:"fcitx5-table-extra~5.1.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-unikey", rpm:"fcitx5-unikey~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-unikey-debuginfo", rpm:"fcitx5-unikey-debuginfo~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-unikey-debugsource", rpm:"fcitx5-unikey-debugsource~5.1.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-zhuyin", rpm:"fcitx5-zhuyin~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-zhuyin-data", rpm:"fcitx5-zhuyin-data~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-zhuyin-debuginfo", rpm:"fcitx5-zhuyin-debuginfo~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fcitx5-zhuyin-debugsource", rpm:"fcitx5-zhuyin-debugsource~5.1.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcm-fcitx5", rpm:"kcm-fcitx5~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kcm-fcitx5-debuginfo", rpm:"kcm-fcitx5-debuginfo~5.1.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libime", rpm:"libime~1.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libime-data", rpm:"libime-data~1.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libime-debuginfo", rpm:"libime-debuginfo~1.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libime-debugsource", rpm:"libime-debugsource~1.1.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libime-devel", rpm:"libime-devel~1.1.12~1.fc42", rls:"FC42"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4387");
  script_cve_id("CVE-2024-39936");
  script_tag(name:"creation_date", value:"2025-12-01 04:24:51 +0000 (Mon, 01 Dec 2025)");
  script_version("2025-12-01T05:45:26+0000");
  script_tag(name:"last_modification", value:"2025-12-01 05:45:26 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:41:50 +0000 (Mon, 08 Jul 2024)");

  script_name("Debian: Security Advisory (DLA-4387-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4387-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4387-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qtbase-opensource-src' package(s) announced via the DLA-4387-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libqt5concurrent5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5dbus5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5network5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5opengl5-dev", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5printsupport5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-ibase", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-mysql", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-odbc", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-psql", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-sqlite", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5sql5-tds", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5test5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5widgets5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5xml5", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-flatpak-platformtheme", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-gtk-platformtheme", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-qmake-bin", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qt5-xdgdesktopportal-platformtheme", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-dev-tools", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc-dev", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-doc-html", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-examples", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qtbase5-private-dev", ver:"5.15.2+dfsg-9+deb11u2", rls:"DEB11"))) {
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

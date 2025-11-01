# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03599.1");
  script_cve_id("CVE-2025-30348", "CVE-2025-5455");
  script_tag(name:"creation_date", value:"2025-10-17 04:07:12 +0000 (Fri, 17 Oct 2025)");
  script_version("2025-10-17T05:39:07+0000");
  script_tag(name:"last_modification", value:"2025-10-17 05:39:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-24 14:08:36 +0000 (Mon, 24 Mar 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03599-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503599-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243958");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-October/022910.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-base' package(s) announced via the SUSE-SU-2025:03599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qt6-base fixes the following issues:

- CVE-2025-5455: processing of malformed data in `qDecodeDataUrl()` can trigger assertion and cause a crash
 (bsc#1243958).
- CVE-2025-30348: complex algorithm used in `encodeText` in QDom when processing XML data can cause low performance
 (bsc#1239896).");

  script_tag(name:"affected", value:"'qt6-base' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libQt6Concurrent6", rpm:"libQt6Concurrent6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Core6", rpm:"libQt6Core6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6DBus6", rpm:"libQt6DBus6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Gui6", rpm:"libQt6Gui6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Network6", rpm:"libQt6Network6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGL6", rpm:"libQt6OpenGL6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGLWidgets6", rpm:"libQt6OpenGLWidgets6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PrintSupport6", rpm:"libQt6PrintSupport6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Sql6", rpm:"libQt6Sql6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Test6", rpm:"libQt6Test6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Widgets6", rpm:"libQt6Widgets6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Xml6", rpm:"libQt6Xml6~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-common-devel", rpm:"qt6-base-common-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-devel", rpm:"qt6-base-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-html", rpm:"qt6-base-docs-html~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-qch", rpm:"qt6-base-docs-qch~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-examples", rpm:"qt6-base-examples~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-private-devel", rpm:"qt6-base-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-concurrent-devel", rpm:"qt6-concurrent-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-devel", rpm:"qt6-core-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-private-devel", rpm:"qt6-core-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-devel", rpm:"qt6-dbus-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-private-devel", rpm:"qt6-dbus-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-docs-common", rpm:"qt6-docs-common~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-exampleicons-devel-static", rpm:"qt6-exampleicons-devel-static~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-devel", rpm:"qt6-gui-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-private-devel", rpm:"qt6-gui-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-devel-static", rpm:"qt6-kmssupport-devel-static~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-private-devel", rpm:"qt6-kmssupport-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-devel", rpm:"qt6-network-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-private-devel", rpm:"qt6-network-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-tls", rpm:"qt6-network-tls~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-glib", rpm:"qt6-networkinformation-glib~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-nm", rpm:"qt6-networkinformation-nm~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-devel", rpm:"qt6-opengl-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-private-devel", rpm:"qt6-opengl-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-openglwidgets-devel", rpm:"qt6-openglwidgets-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-devel-static", rpm:"qt6-platformsupport-devel-static~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-private-devel", rpm:"qt6-platformsupport-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-gtk3", rpm:"qt6-platformtheme-gtk3~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-xdgdesktopportal", rpm:"qt6-platformtheme-xdgdesktopportal~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-cups", rpm:"qt6-printsupport-cups~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-devel", rpm:"qt6-printsupport-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-private-devel", rpm:"qt6-printsupport-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-devel", rpm:"qt6-sql-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-mysql", rpm:"qt6-sql-mysql~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-postgresql", rpm:"qt6-sql-postgresql~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-private-devel", rpm:"qt6-sql-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-sqlite", rpm:"qt6-sql-sqlite~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-unixODBC", rpm:"qt6-sql-unixODBC~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-devel", rpm:"qt6-test-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-private-devel", rpm:"qt6-test-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-devel", rpm:"qt6-widgets-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-private-devel", rpm:"qt6-widgets-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-devel", rpm:"qt6-xml-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-private-devel", rpm:"qt6-xml-private-devel~6.6.3~150600.3.6.1", rls:"openSUSELeap15.6"))) {
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

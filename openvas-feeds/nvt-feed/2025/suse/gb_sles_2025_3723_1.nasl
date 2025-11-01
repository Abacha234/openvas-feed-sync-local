# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3723.1");
  script_cve_id("CVE-2025-30348", "CVE-2025-5455");
  script_tag(name:"creation_date", value:"2025-10-24 04:12:53 +0000 (Fri, 24 Oct 2025)");
  script_version("2025-10-27T05:40:39+0000");
  script_tag(name:"last_modification", value:"2025-10-27 05:40:39 +0000 (Mon, 27 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-24 14:08:36 +0000 (Mon, 24 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3723-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253723-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243958");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-October/022969.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2025:3723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtbase fixes the following issues:

Security issues fixed:

- CVE-2025-5455: processing of malformed data in `qDecodeDataUrl()` can trigger assertion and cause a crash
 (bsc#1243958).
- CVE-2025-30348: complex algorithm used in `encodeText` in QDom when processing XML data can cause low performance
 (bsc#1239896).

Other issues fixed:

- Initialize a member variable in `QObjectPrivate::Signal` that was uninitialized under some circumstances.
- Fix a crash when parsing a particular glyph in a particular font.
- Avoid repeatedly registering xsettings callbacks when switching cursor themes.
- Check validity of RandR output info before using it.
- Fix reparenting a window so it takes effect even if there are no other state changes to the window.");

  script_tag(name:"affected", value:"'libqt5-qtbase' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent-devel", rpm:"libQt5Concurrent-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5", rpm:"libQt5Concurrent5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-devel", rpm:"libQt5Core-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-private-headers-devel", rpm:"libQt5Core-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5", rpm:"libQt5Core5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-devel", rpm:"libQt5DBus-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-private-headers-devel", rpm:"libQt5DBus-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5", rpm:"libQt5DBus5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-devel", rpm:"libQt5Gui-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-private-headers-devel", rpm:"libQt5Gui-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5", rpm:"libQt5Gui5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-devel-static", rpm:"libQt5KmsSupport-devel-static~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-private-headers-devel", rpm:"libQt5KmsSupport-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-devel", rpm:"libQt5Network-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-private-headers-devel", rpm:"libQt5Network-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5", rpm:"libQt5Network5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-devel", rpm:"libQt5OpenGL-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-private-headers-devel", rpm:"libQt5OpenGL-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5", rpm:"libQt5OpenGL5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformHeaders-devel", rpm:"libQt5PlatformHeaders-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-devel-static", rpm:"libQt5PlatformSupport-devel-static~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-private-headers-devel", rpm:"libQt5PlatformSupport-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-devel", rpm:"libQt5PrintSupport-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-private-headers-devel", rpm:"libQt5PrintSupport-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5", rpm:"libQt5PrintSupport5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-devel", rpm:"libQt5Sql-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-private-headers-devel", rpm:"libQt5Sql-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5", rpm:"libQt5Sql5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite", rpm:"libQt5Sql5-sqlite~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-devel", rpm:"libQt5Test-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-private-headers-devel", rpm:"libQt5Test-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5", rpm:"libQt5Test5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-devel", rpm:"libQt5Widgets-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-private-headers-devel", rpm:"libQt5Widgets-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5", rpm:"libQt5Widgets5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml-devel", rpm:"libQt5Xml-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5", rpm:"libQt5Xml5~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-common-devel", rpm:"libqt5-qtbase-common-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-devel", rpm:"libqt5-qtbase-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-private-headers-devel", rpm:"libqt5-qtbase-private-headers-devel~5.15.12+kde151~150600.3.9.1", rls:"SLES15.0SP6"))) {
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

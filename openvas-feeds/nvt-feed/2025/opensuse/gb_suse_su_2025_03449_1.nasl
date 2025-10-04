# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03449.1");
  script_cve_id("CVE-2025-50422");
  script_tag(name:"creation_date", value:"2025-10-03 04:06:43 +0000 (Fri, 03 Oct 2025)");
  script_version("2025-10-03T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-10-03 15:40:40 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03449-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03449-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503449-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247589");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/041995.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cairo' package(s) announced via the SUSE-SU-2025:03449-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cairo fixes the following issues:

- CVE-2025-50422: Fixed Poppler crash on malformed input (bsc#1247589)

- Update to version 1.18.4:
 + The dependency on LZO has been made optional through a build
 time configuration toggle.
 + You can build Cairo against a Freetype installation that does
 not have the FT_Color type.
 + Cairo tests now build on Solaris 11.4 with GCC 14.
 + The DirectWrite backend now builds on MINGW 11.
 + The DirectWrite backend now supports font variations and proper
 glyph coverage.
- Use tarball in lieu of source service due to freedesktop gitlab
 migration, will switch back at next release at the latest.
- Add pkgconfig(lzo2) BuildRequires: New optional dependency, build
 lzo2 support feature.

- Convert to source service: allows for easier upgrades by the
 GNOME team.

- Update to version 1.18.2:
 + The malloc-stats code has been removed from the tests directory
 + Cairo now requires a version of pixman equal to, or newer than,
 0.40.
 + There have been multiple build fixes for newer versions of GCC
 for MSVC, for Solaris, and on macOS 10.7.
 + PNG errors caused by loading malformed data are correctly
 propagated to callers, so they can handle the case.
 + Both stroke and fill colors are now set when showing glyphs on
 a PDF surface.
 + All the font options are copied when creating a fallback font
 object.
 + When drawing text on macOS, Cairo now tries harder to select
 the appropriate font name.
 + Cairo now prefers the COLRv1 table inside a font, if one is
 available.
 + Cairo requires a C11 toolchain when building.");

  script_tag(name:"affected", value:"'cairo' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-32bit", rpm:"cairo-devel-32bit~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools", rpm:"cairo-tools~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit", rpm:"libcairo-gobject2-32bit~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit", rpm:"libcairo-script-interpreter2-32bit~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.18.4~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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

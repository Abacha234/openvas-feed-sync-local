# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4335.1");
  script_cve_id("CVE-2025-10921");
  script_tag(name:"creation_date", value:"2025-12-11 04:17:15 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4335-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4335-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254335-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250496");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023451.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gegl' package(s) announced via the SUSE-SU-2025:4335-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gegl fixes the following issues:

- CVE-2025-10921: lack of proper validation of user-supplied data when parsing HDR files can lead to RCE (bsc#1250496).");

  script_tag(name:"affected", value:"'gegl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gegl", rpm:"gegl~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gegl-0_4", rpm:"gegl-0_4~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gegl-0_4-lang", rpm:"gegl-0_4-lang~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gegl-devel", rpm:"gegl-devel~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gegl-doc", rpm:"gegl-doc~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgegl-0_4-0", rpm:"libgegl-0_4-0~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgegl-0_4-0-32bit", rpm:"libgegl-0_4-0-32bit~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gegl-0_4", rpm:"typelib-1_0-Gegl-0_4~0.4.46~150600.4.3.1", rls:"openSUSELeap15.6"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4325.1");
  script_cve_id("CVE-2025-12817", "CVE-2025-12818");
  script_tag(name:"creation_date", value:"2025-12-11 04:17:15 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4325-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4325-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254325-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253333");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023446.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql13' package(s) announced via the SUSE-SU-2025:4325-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql13 fixes the following issues:

Upgraded to 13.23:

- CVE-2025-12817: Fixed missing check for CREATE privileges on the schema in CREATE STATISTICS (bsc#1253332)
- CVE-2025-12818: Fixed integer overflow in allocation-size calculations within libpq (bsc#1253333)

Other fixes:

- Use %product_libs_llvm_ver to determine the LLVM version.
- Remove conditionals for obsolete PostgreSQL releases.
- Sync spec file from version 18.");

  script_tag(name:"affected", value:"'postgresql13' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"postgresql13", rpm:"postgresql13~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-contrib", rpm:"postgresql13-contrib~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-devel", rpm:"postgresql13-devel~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-docs", rpm:"postgresql13-docs~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit", rpm:"postgresql13-llvmjit~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-llvmjit-devel", rpm:"postgresql13-llvmjit-devel~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plperl", rpm:"postgresql13-plperl~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-plpython", rpm:"postgresql13-plpython~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-pltcl", rpm:"postgresql13-pltcl~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server", rpm:"postgresql13-server~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-server-devel", rpm:"postgresql13-server-devel~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql13-test", rpm:"postgresql13-test~13.23~150600.14.14.1", rls:"openSUSELeap15.6"))) {
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

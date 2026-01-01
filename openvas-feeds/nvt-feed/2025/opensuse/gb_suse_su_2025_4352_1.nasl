# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4352.1");
  script_cve_id("CVE-2025-6075", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2025-12-11 12:20:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4352-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254352-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252974");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023520.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310' package(s) announced via the SUSE-SU-2025:4352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:

Update to 3.10.19:

- CVE-2025-6075: Fixed simple quadratic complexity vulnerabilities of os.path.expandvars(). (bsc#1252974)
- CVE-2025-8291: Check the validity the ZIP64 End of Central Directory (EOCD). (bsc#1251305)");

  script_tag(name:"affected", value:"'python310' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit", rpm:"libpython3_10-1_0-32bit~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit", rpm:"python310-32bit~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit", rpm:"python310-base-32bit~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc", rpm:"python310-doc~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc-devhelp", rpm:"python310-doc-devhelp~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite", rpm:"python310-testsuite~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.19~150400.4.91.3", rls:"openSUSELeap15.6"))) {
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

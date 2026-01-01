# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4425.1");
  script_cve_id("CVE-2025-58436");
  script_tag(name:"creation_date", value:"2025-12-19 04:19:24 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:24:12 +0000 (Thu, 04 Dec 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4425-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4425-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254425-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254353");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023570.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2025:4425-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

Security issues fixed:

- CVE-2025-58436: single client sending slow messages to cupsd can delay the application and make it unusable for other
 clients (bsc#1244057).

Other issues fixed:

- Update the CVE-2025-58436 patch to fix a regression that causes GTK applications to hang (bsc#1254353).");

  script_tag(name:"affected", value:"'cups' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.83.1", rls:"openSUSELeap15.6"))) {
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

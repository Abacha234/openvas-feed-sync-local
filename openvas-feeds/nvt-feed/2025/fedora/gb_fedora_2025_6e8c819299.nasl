# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.6101899819299");
  script_tag(name:"creation_date", value:"2025-12-18 04:17:43 +0000 (Thu, 18 Dec 2025)");
  script_version("2025-12-18T05:46:55+0000");
  script_tag(name:"last_modification", value:"2025-12-18 05:46:55 +0000 (Thu, 18 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-6e8c819299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6e8c819299");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6e8c819299");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2025-65637");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-facebook-time' package(s) announced via the FEDORA-2025-6e8c819299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update logrus for [link moved to references]");

  script_tag(name:"affected", value:"'golang-github-facebook-time' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"calnex", rpm:"calnex~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"calnex-debuginfo", rpm:"calnex-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbclock", rpm:"fbclock~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fbclock-debuginfo", rpm:"fbclock-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time", rpm:"golang-github-facebook-time~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time-debuginfo", rpm:"golang-github-facebook-time-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time-debugsource", rpm:"golang-github-facebook-time-debugsource~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-facebook-time-vendor-licenses", rpm:"golang-github-facebook-time-vendor-licenses~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpcheck", rpm:"ntpcheck~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpcheck-debuginfo", rpm:"ntpcheck-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpresponder", rpm:"ntpresponder~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpresponder-debuginfo", rpm:"ntpresponder-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pshark", rpm:"pshark~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pshark-debuginfo", rpm:"pshark-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptp4u", rpm:"ptp4u~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptp4u-debuginfo", rpm:"ptp4u-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptpcheck", rpm:"ptpcheck~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ptpcheck-debuginfo", rpm:"ptpcheck-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sptp", rpm:"sptp~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sptp-debuginfo", rpm:"sptp-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ziffy", rpm:"ziffy~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ziffy-debuginfo", rpm:"ziffy-debuginfo~0^20251216git61f7510~2.fc43", rls:"FC43"))) {
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

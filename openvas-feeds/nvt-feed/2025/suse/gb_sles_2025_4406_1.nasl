# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4406.1");
  script_cve_id("CVE-2025-12817", "CVE-2025-12818");
  script_tag(name:"creation_date", value:"2025-12-16 16:47:44 +0000 (Tue, 16 Dec 2025)");
  script_version("2025-12-17T05:46:28+0000");
  script_tag(name:"last_modification", value:"2025-12-17 05:46:28 +0000 (Wed, 17 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4406-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4406-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254406-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253333");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023551.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql15' package(s) announced via the SUSE-SU-2025:4406-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql15 fixes the following issues:

Upgraded to 15.15:

- CVE-2025-12817: Fixed missing check for CREATE privileges on the schema in CREATE STATISTICS (bsc#1253332)
- CVE-2025-12818: Fixed integer overflow in allocation-size calculations within libpq (bsc#1253333)

Other fixes:

- Use %product_libs_llvm_ver to determine the LLVM version.
- Remove conditionals for obsolete PostgreSQL releases.
- Sync spec file from version 18.");

  script_tag(name:"affected", value:"'postgresql15' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel", rpm:"postgresql15-server-devel~15.15~150200.5.49.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel", rpm:"postgresql15-server-devel~15.15~150200.5.49.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel", rpm:"postgresql15-server-devel~15.15~150200.5.49.2", rls:"SLES15.0SP5"))) {
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

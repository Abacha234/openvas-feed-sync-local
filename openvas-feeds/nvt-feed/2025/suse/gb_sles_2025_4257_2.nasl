# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4257.2");
  script_cve_id("CVE-2025-6075", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2025-12-16 16:47:44 +0000 (Tue, 16 Dec 2025)");
  script_version("2025-12-17T05:46:28+0000");
  script_tag(name:"last_modification", value:"2025-12-17 05:46:28 +0000 (Wed, 17 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4257-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4257-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254257-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252974");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023544.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311' package(s) announced via the SUSE-SU-2025:4257-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

Update to 3.11.14:

 - CVE-2025-6075: Fixed simple quadratic complexity vulnerabilities of os.path.expandvars() (bsc#1252974)
 - CVE-2025-8291: Fixed validity of the ZIP64 End of Central Directory (EOCD) not checked by the 'zipfile' module (bsc#1251305)");

  script_tag(name:"affected", value:"'python311' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.14~150400.9.69.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.14~150400.9.69.1", rls:"SLES15.0SP5"))) {
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

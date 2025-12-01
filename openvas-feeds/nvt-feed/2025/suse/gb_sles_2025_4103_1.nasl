# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4103.1");
  script_cve_id("CVE-2025-55752", "CVE-2025-55754", "CVE-2025-61795");
  script_tag(name:"creation_date", value:"2025-11-17 04:16:08 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4103-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254103-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252905");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat10' package(s) announced via the SUSE-SU-2025:4103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat10 fixes the following issues:

Update to Tomcat 10.1.48

 - CVE-2025-55752: Fixed directory traversal via rewrite with possible RCE if PUT
 is enabled (bsc#1252753)
 - CVE-2025-55754: Fixed improper neutralization of escape, meta, or control
 sequences vulnerability (bsc#1252905)
 - CVE-2025-61795: Fixed denial of service due to temporary copies during
 the processing of multipart upload (bsc#1252756)");

  script_tag(name:"affected", value:"'tomcat10' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat10", rpm:"tomcat10~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-admin-webapps", rpm:"tomcat10-admin-webapps~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-el-5_0-api", rpm:"tomcat10-el-5_0-api~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-jsp-3_1-api", rpm:"tomcat10-jsp-3_1-api~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-lib", rpm:"tomcat10-lib~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-servlet-6_0-api", rpm:"tomcat10-servlet-6_0-api~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat10-webapps", rpm:"tomcat10-webapps~10.1.48~150200.5.54.1", rls:"SLES15.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21162.1");
  script_cve_id("CVE-2025-53057", "CVE-2025-53066", "CVE-2025-61748");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-21 20:20:47 +0000 (Tue, 21 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21162-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521162-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252418");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-21-openjdk' package(s) announced via the SUSE-SU-2025:21162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-21-openjdk fixes the following issues:

Update to upstream tag jdk-21.0.9+10 (October 2025 CPU):

- CVE-2025-53066: Fixed enhance path factories (bsc#1252417).
- CVE-2025-61748: Fixed enhance string handling (bsc#1252418).
- CVE-2025-53057: Fixed enhance certificate handling (bsc#1252414).

Other bug fixes:

- Do not embed rebuild counter (bsc#1246806)");

  script_tag(name:"affected", value:"'java-21-openjdk' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk", rpm:"java-21-openjdk~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-demo", rpm:"java-21-openjdk-demo~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-devel", rpm:"java-21-openjdk-devel~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-headless", rpm:"java-21-openjdk-headless~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-javadoc", rpm:"java-21-openjdk-javadoc~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-jmods", rpm:"java-21-openjdk-jmods~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-21-openjdk-src", rpm:"java-21-openjdk-src~21.0.9.0~160000.1.1", rls:"SLES16.0.0"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3900.1");
  script_cve_id("CVE-2025-43718", "CVE-2025-52885");
  script_tag(name:"creation_date", value:"2025-11-03 04:17:53 +0000 (Mon, 03 Nov 2025)");
  script_version("2025-11-03T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-03 05:40:08 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3900-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3900-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253900-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251940");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-October/023129.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2025:3900-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

- CVE-2025-43718: Fixed uncontrolled recursion in the regex-based metadata parser when processing specially crafted PDF files allows for stack exhaustion and denial of service (bsc#1250908).
- CVE-2025-52885: Fixed raw pointers can lead to dangling pointers when the vector is resized (bsc#1251940).");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler126", rpm:"libpoppler126~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~23.01.0~150500.3.26.1", rls:"SLES15.0SP5"))) {
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

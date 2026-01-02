# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4514.1");
  script_cve_id("CVE-2025-12105", "CVE-2025-32911");
  script_tag(name:"creation_date", value:"2025-12-25 04:26:35 +0000 (Thu, 25 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4514-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4514-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254514-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252555");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the SUSE-SU-2025:4514-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup fixes the following issues:

- CVE-2025-12105: Fixed heap use-after-free in message queue handling during HTTP/2 read completion (bsc#1252555)");

  script_tag(name:"affected", value:"'libsoup' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup-3_0-0", rpm:"libsoup-3_0-0~3.0.4~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~3.0.4~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~3.0.4~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-3_0", rpm:"typelib-1_0-Soup-3_0~3.0.4~150400.3.21.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libsoup-3_0-0", rpm:"libsoup-3_0-0~3.0.4~150400.3.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~3.0.4~150400.3.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~3.0.4~150400.3.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-3_0", rpm:"typelib-1_0-Soup-3_0~3.0.4~150400.3.21.1", rls:"SLES15.0SP5"))) {
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

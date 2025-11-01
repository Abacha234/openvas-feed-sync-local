# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3743.1");
  script_cve_id("CVE-2025-11731");
  script_tag(name:"creation_date", value:"2025-10-24 04:12:53 +0000 (Fri, 24 Oct 2025)");
  script_version("2025-10-27T05:40:39+0000");
  script_tag(name:"last_modification", value:"2025-10-27 05:40:39 +0000 (Mon, 27 Oct 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-14 06:15:34 +0000 (Tue, 14 Oct 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3743-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253743-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251979");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042270.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the SUSE-SU-2025:3743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxslt fixes the following issues:

 - CVE-2025-11731: fixed a type confusion in exsltFuncResultComp function that could cause a denial of service (bsc#1251979)");

  script_tag(name:"affected", value:"'libxslt' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.32~150000.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-tools", rpm:"libxslt-tools~1.1.32~150000.3.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt1", rpm:"libxslt1~1.1.32~150000.3.28.1", rls:"SLES15.0SP3"))) {
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

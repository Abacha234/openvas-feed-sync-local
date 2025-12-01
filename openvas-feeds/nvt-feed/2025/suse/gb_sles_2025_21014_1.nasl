# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21014.1");
  script_cve_id("CVE-2025-64181");
  script_tag(name:"creation_date", value:"2025-11-28 04:13:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21014-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521014-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253233");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023382.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the SUSE-SU-2025:21014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openexr fixes the following issues:

- CVE-2025-64181: Fixed use of uninitialized memory in function generic_unpack() (bsc#1253233)");

  script_tag(name:"affected", value:"'openexr' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libIex-3_2-31", rpm:"libIex-3_2-31~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIex-3_2-31-x86-64-v3", rpm:"libIex-3_2-31-x86-64-v3~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmThread-3_2-31", rpm:"libIlmThread-3_2-31~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libIlmThread-3_2-31-x86-64-v3", rpm:"libIlmThread-3_2-31-x86-64-v3~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXR-3_2-31", rpm:"libOpenEXR-3_2-31~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXR-3_2-31-x86-64-v3", rpm:"libOpenEXR-3_2-31-x86-64-v3~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRCore-3_2-31", rpm:"libOpenEXRCore-3_2-31~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRCore-3_2-31-x86-64-v3", rpm:"libOpenEXRCore-3_2-31-x86-64-v3~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRUtil-3_2-31", rpm:"libOpenEXRUtil-3_2-31~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenEXRUtil-3_2-31-x86-64-v3", rpm:"libOpenEXRUtil-3_2-31-x86-64-v3~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-doc", rpm:"openexr-doc~3.2.2~160000.3.1", rls:"SLES16.0.0"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4094.1");
  script_cve_id("CVE-2025-46404", "CVE-2025-46705", "CVE-2025-46784", "CVE-2025-47151");
  script_tag(name:"creation_date", value:"2025-11-17 04:16:08 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-05 23:16:04 +0000 (Wed, 05 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4094-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4094-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254094-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253095");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023279.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lasso' package(s) announced via the SUSE-SU-2025:4094-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lasso fixes the following issues:

- CVE-2025-46784: Fixed memory exhaustion in Entr'ouvert Lasso (bsc#1253094)
- CVE-2025-46404: Fixed denial of service in Entr'ouvert Lasso (bsc#1253092)
- CVE-2025-46705: Fixed denial of service in Entr'ouvert Lasso (bsc#1253093)
- CVE-2025-47151: Fixed type confusion vulnerability in the
 lasso_node_impl_init_from_xml functionality (bsc#1253095)");

  script_tag(name:"affected", value:"'lasso' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"liblasso-devel", rpm:"liblasso-devel~2.6.1~8.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblasso3", rpm:"liblasso3~2.6.1~8.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lasso", rpm:"python3-lasso~2.6.1~8.12.1", rls:"SLES12.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21144.1");
  script_cve_id("CVE-2025-30706");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 21:16:00 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21144-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521144-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241693");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023513.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-connector-java' package(s) announced via the SUSE-SU-2025:21144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mysql-connector-java fixes the following issues:

- Upgrade to Version 9.3.0
 - CVE-2025-30706: Fixed Connector/J vulnerability (bsc#1241693)
 - Updatable ResultSet fails with 'Parameter index out of range'.
 - Fixed Resultset UPDATE methods not checking validity of ResultSet.
 - DatabaseMetaData clean up.
 - Fixed implement missing methods in DatabaseMetaDataUsingInfoSchema.
 - Fixed procedure execution failing when the parameter name contains escape character.
 - Fixed allow only Krb5LoginModule in Kerberos authentication.
 - Fixed EXECUTE on CallableStatement resulting in ArrayIndexOutOfBoundsException.
 - Mysql connector use an uneffective way to match numericValue.
 - Fixed parameter index validation not proper in CallableStatement");

  script_tag(name:"affected", value:"'mysql-connector-java' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"mysql-connector-java", rpm:"mysql-connector-java~9.3.0~160000.1.1", rls:"SLES16.0.0"))) {
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

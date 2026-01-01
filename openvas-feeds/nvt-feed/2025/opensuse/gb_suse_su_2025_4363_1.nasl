# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4363.1");
  script_cve_id("CVE-2025-12817", "CVE-2025-12818");
  script_tag(name:"creation_date", value:"2025-12-15 04:21:19 +0000 (Mon, 15 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4363-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4363-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254363-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253333");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023522.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-3142/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-3171/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/18/release-18.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/17.7/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/18.1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql17, postgresql18' package(s) announced via the SUSE-SU-2025:4363-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql17, postgresql18 fixes the following issues:

Changes in postgresql18:

- Fix build with uring for post SLE15 code streams.

Update to 18.1:

 * [links moved to references]
 * bsc#1253332, CVE-2025-12817: Missing check for CREATE
 privileges on the schema in CREATE STATISTICS allowed table
 owners to create statistics in any schema, potentially leading
 to unexpected naming conflicts.
 * bsc#1253333, CVE-2025-12818: Several places in libpq were not
 sufficiently careful about computing the required size of a
 memory allocation. Sufficiently large inputs could cause
 integer overflow, resulting in an undersized buffer, which
 would then lead to writing past the end of the buffer.

- pg_config --libs returns -lnuma so we need to require it.

Update to 18.0:

 * [links moved to references]


Changes in postgresql17:

Update to 17.7:

 * [links moved to references]
 * bsc#1253332, CVE-2025-12817: Missing check for CREATE
 privileges on the schema in CREATE STATISTICS allowed table
 owners to create statistics in any schema, potentially leading
 to unexpected naming conflicts.
 * bsc#1253333, CVE-2025-12818: Several places in libpq were not
 sufficiently careful about computing the required size of a
 memory allocation. Sufficiently large inputs could cause
 integer overflow, resulting in an undersized buffer, which
 would then lead to writing past the end of the buffer.

- switch library to pg 18");

  script_tag(name:"affected", value:"'postgresql17, postgresql18' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-32bit", rpm:"libecpg6-32bit~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-32bit", rpm:"libpq5-32bit~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-llvmjit", rpm:"postgresql-llvmjit~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-llvmjit-devel", rpm:"postgresql-llvmjit-devel~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server-devel", rpm:"postgresql-server-devel~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-test", rpm:"postgresql-test~18~150600.17.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17", rpm:"postgresql17~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-contrib", rpm:"postgresql17-contrib~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-devel", rpm:"postgresql17-devel~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-docs", rpm:"postgresql17-docs~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-llvmjit", rpm:"postgresql17-llvmjit~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-llvmjit-devel", rpm:"postgresql17-llvmjit-devel~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-plperl", rpm:"postgresql17-plperl~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-plpython", rpm:"postgresql17-plpython~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-pltcl", rpm:"postgresql17-pltcl~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-server", rpm:"postgresql17-server~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-server-devel", rpm:"postgresql17-server-devel~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql17-test", rpm:"postgresql17-test~17.7~150600.13.19.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18", rpm:"postgresql18~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-contrib", rpm:"postgresql18-contrib~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-devel", rpm:"postgresql18-devel~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-docs", rpm:"postgresql18-docs~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-llvmjit", rpm:"postgresql18-llvmjit~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-llvmjit-devel", rpm:"postgresql18-llvmjit-devel~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-plperl", rpm:"postgresql18-plperl~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-plpython", rpm:"postgresql18-plpython~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-pltcl", rpm:"postgresql18-pltcl~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-server", rpm:"postgresql18-server~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-server-devel", rpm:"postgresql18-server-devel~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql18-test", rpm:"postgresql18-test~18.1~150600.13.3.1", rls:"openSUSELeap15.6"))) {
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

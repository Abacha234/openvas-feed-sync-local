# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9910189740961017");
  script_cve_id("CVE-2025-14177", "CVE-2025-14178", "CVE-2025-14180");
  script_tag(name:"creation_date", value:"2025-12-19 04:19:11 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-ce8a4096e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ce8a4096e7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ce8a4096e7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20286");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20329");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20374");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20395");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20426");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20435");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20439");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20442");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20483");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20491");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20492");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20511");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20528");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20583");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20601");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20602");
  script_xref(name:"URL", value:"https://github.com/php/php-src/issues/20614");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-3237-qqm7-mfv7");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-8xr5-qppj-gvwj");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-h96m-rvf9-jgm2");
  script_xref(name:"URL", value:"https://github.com/php/php-src/security/advisories/GHSA-www2-q4fc-65wf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the FEDORA-2025-ce8a4096e7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**PHP version 8.4.16** (18 Dec 2025)

**Core:**

* Sync all boost.context files with release 1.86.0. (mvorisek)
* Fixed bug [GH-20435]([link moved to references]) (SensitiveParameter doesn't work for named argument passing to variadic parameter). (ndossche)
* Fixed bug [GH-20286]([link moved to references]) (use-after-destroy during userland stream_close()). (ndossche, David Carlier)

**Bz2:**

* Fix assertion failures resulting in crashes with stream filter object parameters. (ndossche)

**Date:**

* Fix crashes when trying to instantiate uninstantiable classes via date static constructors. (ndossche)

**DOM:**

* Fix memory leak when edge case is hit when registering xpath callback. (ndossche)
* Fixed bug [GH-20395]([link moved to references]) (querySelector and querySelectorAll requires elements in $selectors to be lowercase). (ndossche)
* Fix missing NUL byte check on C14NFile(). (ndossche)

**Fibers:**

* Fixed bug [GH-20483]([link moved to references]) (ASAN stack overflow with fiber.stack_size INI small value). (David Carlier)

**FTP:**

* Fixed bug [GH-20601]([link moved to references]) (ftp_connect overflow on timeout). (David Carlier)

**GD:**

* Fixed bug [GH-20511]([link moved to references]) (imagegammacorrect out of range input/output values). (David Carlier)
* Fixed bug [GH-20602]([link moved to references]) (imagescale overflow with large height values). (David Carlier)

**Intl:**

* Fixed bug [GH-20426]([link moved to references]) (Spoofchecker::setRestrictionLevel() error message suggests missing constants). (DanielEScherzer)

**LibXML:**

* Fix some deprecations on newer libxml versions regarding input buffer/parser handling. (ndossche)

**MbString:**

* Fixed bug [GH-20491]([link moved to references]) (SLES15 compile error with mbstring oniguruma). (ndossche)
* Fixed bug [GH-20492]([link moved to references]) (mbstring compile warning due to non-strings). (ndossche)

**MySQLnd:**

* Fixed bug [GH-20528]([link moved to references]) (Regression breaks mysql connexion using an IPv6 address enclosed in square brackets). (Remi)

**Opcache:**

* Fixed bug [GH-20329]([link moved to references]) (opcache.file_cache broken with full interned string buffer). (Arnaud)

**PDO:**

* Fixed [GHSA-8xr5-qppj-gvwj]([link moved to references]) (PDO quoting result null deref). (**CVE-2025-14180**) (Jakub Zelenka)

**Phar:**

* Fixed bug [GH-20442]([link moved to references]) (Phar does not respect case-insensitiveness of __halt_compiler() when reading stub). (ndossche, TimWolla)
* Fix broken return value of fflush() for phar file entries. (ndossche)
* Fix assertion failure when fseeking a phar file out of bounds. (ndossche)

**PHPDBG:**

* Fixed ZPP type violation in phpdbg_get_executable() and phpdbg_end_oplog(). (Girgias)

**SPL:**

* Fixed bug [GH-20614]([link moved to references]) (SplFixedArray incorrectly handles references in deserialization). ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-bcmath-debuginfo", rpm:"php-bcmath-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli-debuginfo", rpm:"php-cli-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common-debuginfo", rpm:"php-common-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dba-debuginfo", rpm:"php-dba-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg", rpm:"php-dbg~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-dbg-debuginfo", rpm:"php-dbg-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-debugsource", rpm:"php-debugsource~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-embedded-debuginfo", rpm:"php-embedded-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-enchant-debuginfo", rpm:"php-enchant-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi", rpm:"php-ffi~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ffi-debuginfo", rpm:"php-ffi-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm", rpm:"php-fpm~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-fpm-debuginfo", rpm:"php-fpm-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gd-debuginfo", rpm:"php-gd-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp", rpm:"php-gmp~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-gmp-debuginfo", rpm:"php-gmp-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-intl-debuginfo", rpm:"php-intl-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ldap-debuginfo", rpm:"php-ldap-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mbstring-debuginfo", rpm:"php-mbstring-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd", rpm:"php-mysqlnd~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mysqlnd-debuginfo", rpm:"php-mysqlnd-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-odbc-debuginfo", rpm:"php-odbc-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache", rpm:"php-opcache~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-opcache-debuginfo", rpm:"php-opcache-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib", rpm:"php-pdo-dblib~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-dblib-debuginfo", rpm:"php-pdo-dblib-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-debuginfo", rpm:"php-pdo-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird", rpm:"php-pdo-firebird~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pdo-firebird-debuginfo", rpm:"php-pdo-firebird-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-pgsql-debuginfo", rpm:"php-pgsql-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process", rpm:"php-process~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-process-debuginfo", rpm:"php-process-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-snmp-debuginfo", rpm:"php-snmp-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-soap-debuginfo", rpm:"php-soap-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium", rpm:"php-sodium~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-sodium-debuginfo", rpm:"php-sodium-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tidy-debuginfo", rpm:"php-tidy-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~8.4.16~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-xml-debuginfo", rpm:"php-xml-debuginfo~8.4.16~1.fc42", rls:"FC42"))) {
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

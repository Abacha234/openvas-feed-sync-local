# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.96219919100978");
  script_cve_id("CVE-2025-58098", "CVE-2025-65082", "CVE-2025-66200");
  script_tag(name:"creation_date", value:"2025-12-11 12:20:29 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-9621c19da8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9621c19da8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9621c19da8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419768");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420206");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420207");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420208");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420209");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420214");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420215");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the FEDORA-2025-9621c19da8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- version update
- security update");

  script_tag(name:"affected", value:"'httpd' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-core", rpm:"httpd-core~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-core-debuginfo", rpm:"httpd-core-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-debugsource", rpm:"httpd-debugsource~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-filesystem", rpm:"httpd-filesystem~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools-debuginfo", rpm:"httpd-tools-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ldap", rpm:"mod_ldap~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ldap-debuginfo", rpm:"mod_ldap-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_lua", rpm:"mod_lua~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_lua-debuginfo", rpm:"mod_lua-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_proxy_html", rpm:"mod_proxy_html~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_proxy_html-debuginfo", rpm:"mod_proxy_html-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_session-debuginfo", rpm:"mod_session-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.66~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl-debuginfo", rpm:"mod_ssl-debuginfo~2.4.66~1.fc43", rls:"FC43"))) {
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

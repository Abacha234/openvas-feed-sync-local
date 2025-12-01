# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0301");
  script_cve_id("CVE-2024-42516", "CVE-2024-43204", "CVE-2024-47252", "CVE-2025-23048", "CVE-2025-49630", "CVE-2025-49812", "CVE-2025-53020", "CVE-2025-54090");
  script_tag(name:"creation_date", value:"2025-11-18 04:10:20 +0000 (Tue, 18 Nov 2025)");
  script_version("2025-11-19T05:40:23+0000");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0301");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0301.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34464");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/10");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/6");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/7");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/10/9");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/24/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2025-0301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTTP response splitting. (CVE-2024-42516)
SSRF with mod_headers setting Content-Type header. (CVE-2024-43204)
mod_ssl error log variable escaping. (CVE-2024-47252)
mod_proxy_http2 denial of service. (CVE-2025-49630)
mod_ssl access control bypass with session resumption. (CVE-2025-23048)
mod_ssl TLS upgrade attack. (CVE-2025-49812)
HTTP/2 DoS by Memory Increase. (CVE-2025-53020)
'RewriteCond expr' always evaluates to true in 2.4.64. (CVE-2025-54090)
You will find the update delay sometimes causes a failure, just restart
the service after the update.");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_brotli", rpm:"apache-mod_brotli~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.65~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.65~1.mga9", rls:"MAGEIA9"))) {
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

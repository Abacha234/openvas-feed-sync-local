# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0239");
  script_cve_id("CVE-2025-8671");
  script_tag(name:"creation_date", value:"2025-10-17 04:08:53 +0000 (Fri, 17 Oct 2025)");
  script_version("2025-10-17T05:39:07+0000");
  script_tag(name:"last_modification", value:"2025-10-17 05:39:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0239");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0239.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34587");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/08/13/6");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/08/16/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd, varnish' package(s) announced via the MGASA-2025-0239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a denial of service attack can be performed on
cache servers that have the HTTP/2 protocol turned on. An attacker can
create a large number of streams and immediately reset them without ever
reaching the maximum number of concurrent streams allowed for the
session, causing the server to consume unnecessary resources processing
requests for which the response will not be delivered (CVE-2025-8671).");

  script_tag(name:"affected", value:"'lighttpd, varnish' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish-devel", rpm:"lib64varnish-devel~7.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish3", rpm:"lib64varnish3~7.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish-devel", rpm:"libvarnish-devel~7.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish3", rpm:"libvarnish3~7.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_ajp13", rpm:"lighttpd-mod_ajp13~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_auth", rpm:"lighttpd-mod_auth~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_file", rpm:"lighttpd-mod_authn_file~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_deflate", rpm:"lighttpd-mod_deflate~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.80~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varnish", rpm:"varnish~7.7.3~1.mga9", rls:"MAGEIA9"))) {
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

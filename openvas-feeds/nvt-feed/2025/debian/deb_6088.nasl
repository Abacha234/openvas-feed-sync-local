# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.6088");
  script_cve_id("CVE-2025-14177", "CVE-2025-14178", "CVE-2025-14180");
  script_tag(name:"creation_date", value:"2025-12-22 04:20:40 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-6088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB13");

  script_xref(name:"Advisory-ID", value:"DSA-6088-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-6088-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php8.4' package(s) announced via the DSA-6088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'php8.4' package(s) on Debian 13.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php8.4", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libphp8.4-embed", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-bcmath", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-bz2", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-cgi", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-cli", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-common", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-curl", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-dba", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-dev", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-enchant", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-fpm", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-gd", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-gmp", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-interbase", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-intl", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-ldap", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-mbstring", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-mysql", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-odbc", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-opcache", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-pgsql", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-phpdbg", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-readline", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-snmp", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-soap", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-sqlite3", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-sybase", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-tidy", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-xml", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-xsl", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.4-zip", ver:"8.4.16-1~deb13u1", rls:"DEB13"))) {
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

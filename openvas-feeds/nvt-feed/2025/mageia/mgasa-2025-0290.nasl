# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0290");
  script_cve_id("CVE-2025-25186", "CVE-2025-27219", "CVE-2025-27220", "CVE-2025-27221");
  script_tag(name:"creation_date", value:"2025-11-14 04:09:58 +0000 (Fri, 14 Nov 2025)");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-05 14:58:14 +0000 (Wed, 05 Mar 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0290");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0290.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34179");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7418-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2025-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Net::IMAP vulnerable to possible DoS by memory exhaustion.
(CVE-2025-25186)
In the CGI gem before 0.4.2 for Ruby, the CGI::Cookie.parse method in
the CGI library contains a potential Denial of Service (DoS)
vulnerability. The method does not impose any limit on the length of the
raw cookie value it processes. This oversight can lead to excessive
resource consumption when parsing extremely large cookies.
(CVE-2025-27219)
In the CGI gem before 0.4.2 for Ruby, a Regular Expression Denial of
Service (ReDoS) vulnerability exists in the Util#escapeElement method.
(CVE-2025-27220)
In the URI gem before 1.0.3 for Ruby, the URI handling methods
(URI.join, URI#merge, URI#+) have an inadvertent leakage of
authentication credentials because userinfo is retained even after
changing the host. (CVE-2025-27221)");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby3.1", rpm:"lib64ruby3.1~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby3.1", rpm:"libruby3.1~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-RubyGems", rpm:"ruby-RubyGems~3.3.26~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bigdecimal", rpm:"ruby-bigdecimal~3.1.1~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems", rpm:"ruby-bundled-gems~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundler", rpm:"ruby-bundler~2.3.27~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.5.11~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~3.1.5~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-json", rpm:"ruby-json~2.6.1~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~2.0.1~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-psych", rpm:"ruby-psych~4.0.4~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rake", rpm:"ruby-rake~13.0.6~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rbs", rpm:"ruby-rbs~2.7.0~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~6.4.1.1~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rexml", rpm:"ruby-rexml~3.3.9~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rss", rpm:"ruby-rss~0.2.9~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.5.3~47.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-typeprof", rpm:"ruby-typeprof~0.21.3~47.mga9", rls:"MAGEIA9"))) {
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

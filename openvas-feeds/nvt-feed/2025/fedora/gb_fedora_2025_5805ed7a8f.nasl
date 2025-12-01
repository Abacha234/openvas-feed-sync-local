# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.58051011007978102");
  script_cve_id("CVE-2025-58767", "CVE-2025-61594");
  script_tag(name:"creation_date", value:"2025-11-12 04:06:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-30 13:07:07 +0000 (Tue, 30 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-5805ed7a8f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5805ed7a8f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5805ed7a8f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2396204");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the FEDORA-2025-5805ed7a8f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Upgrade to Ruby 3.4.7.
- Fix URI Credential Leakage Bypass previous fixes.
 Resolves: CVE-2025-61594
- Fix REXML denial of service.
 Resolves: rhbz#2396204
 Resolves: CVE-2025-58767");

  script_tag(name:"affected", value:"'ruby' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems", rpm:"ruby-bundled-gems~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems-debuginfo", rpm:"ruby-bundled-gems-debuginfo~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-debugsource", rpm:"ruby-debugsource~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-default-gems", rpm:"ruby-default-gems~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs-debuginfo", rpm:"ruby-libs-debuginfo~3.4.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~3.1.8~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal-debuginfo", rpm:"rubygem-bigdecimal-debuginfo~3.1.8~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bundler", rpm:"rubygem-bundler~2.6.9~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.8.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console-debuginfo", rpm:"rubygem-io-console-debuginfo~0.8.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-irb", rpm:"rubygem-irb~1.14.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~2.9.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json-debuginfo", rpm:"rubygem-json-debuginfo~2.9.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-minitest", rpm:"rubygem-minitest~5.25.4~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-power_assert", rpm:"rubygem-power_assert~2.0.5~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~5.2.2~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych-debuginfo", rpm:"rubygem-psych-debuginfo~5.2.2~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-racc", rpm:"rubygem-racc~1.8.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-racc-debuginfo", rpm:"rubygem-racc-debuginfo~1.8.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rake", rpm:"rubygem-rake~13.2.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rbs", rpm:"rubygem-rbs~3.8.0~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rbs-debuginfo", rpm:"rubygem-rbs-debuginfo~3.8.0~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~6.14.0~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rexml", rpm:"rubygem-rexml~3.4.4~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rss", rpm:"rubygem-rss~0.3.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-test-unit", rpm:"rubygem-test-unit~3.6.7~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-typeprof", rpm:"rubygem-typeprof~0.30.1~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~3.6.9~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems-devel", rpm:"rubygems-devel~3.6.9~26.fc42", rls:"FC42"))) {
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

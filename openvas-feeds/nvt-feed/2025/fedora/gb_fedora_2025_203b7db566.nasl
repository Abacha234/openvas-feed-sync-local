# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.20398710098566");
  script_cve_id("CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572", "CVE-2023-27530", "CVE-2023-27539", "CVE-2024-21510", "CVE-2024-25126", "CVE-2024-26141", "CVE-2024-26143", "CVE-2024-26146", "CVE-2024-28103", "CVE-2025-25184", "CVE-2025-27111", "CVE-2025-27610", "CVE-2025-32441", "CVE-2025-46336", "CVE-2025-46727");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 15:27:55 +0000 (Tue, 11 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-203b7db566)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-203b7db566");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-203b7db566");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2124662");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164714");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164716");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164719");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164721");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164724");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176478");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179649");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2179651");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2185966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2185968");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238177");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265593");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265594");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266388");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266389");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290530");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290531");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2323117");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2338474");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2344660");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2345301");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349810");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351231");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364965");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364966");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2365151");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Changes/Ruby_on_Rails_8.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actioncable, rubygem-actionmailbox, rubygem-actionmailer, rubygem-actionpack, rubygem-actiontext, rubygem-actionview, rubygem-activejob, rubygem-activemodel, rubygem-activerecord, rubygem-activestorage, rubygem-activesupport, rubygem-rack, rubygem-rack-protection, rubygem-rack-session, rubygem-rackup, rubygem-rails, rubygem-railties, rubygem-sinatra' package(s) announced via the FEDORA-2025-203b7db566 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[link moved to references]");

  script_tag(name:"affected", value:"'rubygem-actioncable, rubygem-actionmailbox, rubygem-actionmailer, rubygem-actionpack, rubygem-actiontext, rubygem-actionview, rubygem-activejob, rubygem-activemodel, rubygem-activerecord, rubygem-activestorage, rubygem-activesupport, rubygem-rack, rubygem-rack-protection, rubygem-rack-session, rubygem-rackup, rubygem-rails, rubygem-railties, rubygem-sinatra' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actioncable", rpm:"rubygem-actioncable~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actioncable-doc", rpm:"rubygem-actioncable-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailbox", rpm:"rubygem-actionmailbox~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailbox-doc", rpm:"rubygem-actionmailbox-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailer", rpm:"rubygem-actionmailer~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionmailer-doc", rpm:"rubygem-actionmailer-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionpack", rpm:"rubygem-actionpack~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionpack-doc", rpm:"rubygem-actionpack-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actiontext", rpm:"rubygem-actiontext~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actiontext-doc", rpm:"rubygem-actiontext-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionview", rpm:"rubygem-actionview~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-actionview-doc", rpm:"rubygem-actionview-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activejob", rpm:"rubygem-activejob~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activejob-doc", rpm:"rubygem-activejob-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activemodel", rpm:"rubygem-activemodel~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activemodel-doc", rpm:"rubygem-activemodel-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activerecord", rpm:"rubygem-activerecord~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activerecord-doc", rpm:"rubygem-activerecord-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activestorage", rpm:"rubygem-activestorage~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activestorage-doc", rpm:"rubygem-activestorage-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activesupport", rpm:"rubygem-activesupport~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-activesupport-doc", rpm:"rubygem-activesupport-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack", rpm:"rubygem-rack~3.1.16~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-doc", rpm:"rubygem-rack-doc~3.1.16~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-protection", rpm:"rubygem-rack-protection~4.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-protection-doc", rpm:"rubygem-rack-protection-doc~4.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-session", rpm:"rubygem-rack-session~2.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rack-session-doc", rpm:"rubygem-rack-session-doc~2.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rackup", rpm:"rubygem-rackup~2.2.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rackup-doc", rpm:"rubygem-rackup-doc~2.2.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rails", rpm:"rubygem-rails~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rails-doc", rpm:"rubygem-rails-doc~8.0.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-railties", rpm:"rubygem-railties~8.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-railties-doc", rpm:"rubygem-railties-doc~8.0.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-sinatra", rpm:"rubygem-sinatra~4.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-sinatra-doc", rpm:"rubygem-sinatra-doc~4.1.1~1.fc43", rls:"FC43"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.100497041001009781");
  script_cve_id("CVE-2025-47906", "CVE-2025-47910", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-8556");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-06 09:15:28 +0000 (Wed, 06 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-d4a04dda81)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d4a04dda81");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d4a04dda81");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2386296");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398563");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2399222");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2407762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408031");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408289");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409212");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409499");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409762");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410176");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410450");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410712");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411090");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411349");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411608");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2414902");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gopass-jsonapi' package(s) announced via the FEDORA-2025-d4a04dda81 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.6.0");

  script_tag(name:"affected", value:"'gopass-jsonapi' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gopass-jsonapi", rpm:"gopass-jsonapi~1.16.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gopass-jsonapi-debuginfo", rpm:"gopass-jsonapi-debuginfo~1.16.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gopass-jsonapi-debugsource", rpm:"gopass-jsonapi-debugsource~1.16.0~1.fc43", rls:"FC43"))) {
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

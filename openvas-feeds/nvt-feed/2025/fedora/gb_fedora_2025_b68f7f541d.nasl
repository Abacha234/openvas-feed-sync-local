# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98681027102541100");
  script_cve_id("CVE-2025-40778", "CVE-2025-40780", "CVE-2025-8677");
  script_tag(name:"creation_date", value:"2025-11-17 04:10:17 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-22 16:15:42 +0000 (Wed, 22 Oct 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b68f7f541d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b68f7f541d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b68f7f541d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2394406");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2396295");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406399");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2413104");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/bind9/9.21.14/doc/arm/html/notes.html#notes-for-bind-9-21-14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9-next' package(s) announced via the FEDORA-2025-b68f7f541d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 9.21.14 (rhbz#2394406)

## Security Fixes:

- DNSSEC validation fails if matching but invalid DNSKEY is found. (CVE-2025-8677)
- Address various spoofing attacks. (CVE-2025-40778)
- Cache-poisoning due to weak pseudo-random number generator. (CVE-2025-40780)

## New Features:

- Add dnssec-policy keys configuration check to named-checkconf.
- Add support for synthetic records.
- Support for zone-specific plugins.
- Support for additional tokens in the zone file name template.

## Removed Features:

- Remove randomized RRset ordering.

and bug fixes

[link moved to references]");

  script_tag(name:"affected", value:"'bind9-next' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind9-next", rpm:"bind9-next~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-chroot", rpm:"bind9-next-chroot~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debuginfo", rpm:"bind9-next-debuginfo~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-debugsource", rpm:"bind9-next-debugsource~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils", rpm:"bind9-next-dnssec-utils~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-dnssec-utils-debuginfo", rpm:"bind9-next-dnssec-utils-debuginfo~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-doc", rpm:"bind9-next-doc~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs", rpm:"bind9-next-libs~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-libs-debuginfo", rpm:"bind9-next-libs-debuginfo~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils", rpm:"bind9-next-utils~9.21.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind9-next-utils-debuginfo", rpm:"bind9-next-utils-debuginfo~9.21.14~2.fc43", rls:"FC43"))) {
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

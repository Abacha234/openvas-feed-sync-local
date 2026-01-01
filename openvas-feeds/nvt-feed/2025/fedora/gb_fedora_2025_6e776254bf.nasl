# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.610177625498102");
  script_cve_id("CVE-2025-13630", "CVE-2025-13631", "CVE-2025-13632", "CVE-2025-13633", "CVE-2025-13634", "CVE-2025-13635", "CVE-2025-13636", "CVE-2025-13637", "CVE-2025-13638", "CVE-2025-13639", "CVE-2025-13640", "CVE-2025-13720", "CVE-2025-13721", "CVE-2025-14765", "CVE-2025-14766");
  script_tag(name:"creation_date", value:"2025-12-22 04:21:57 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 19:16:17 +0000 (Thu, 04 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-6e776254bf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6e776254bf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6e776254bf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420939");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423482");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2025-6e776254bf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to cef-143.0.10+g8aed01b + chromium-143.0.7499.146 (rhbz#2423482)

* High CVE-2025-14765: Use after free in WebGPU
* High CVE-2025-14766: Out of bounds read and write in V8
* High CVE-2025-13630: Type Confusion in V8
* High CVE-2025-13631: Inappropriate implementation in Google Updater
* High CVE-2025-13632: Inappropriate implementation in DevTools
* High CVE-2025-13633: Use after free in Digital Credentials
* Medium CVE-2025-13634: Inappropriate implementation in Downloads
* Medium CVE-2025-13720: Bad cast in Loader
* Medium CVE-2025-13721: Race in v8
* Low CVE-2025-13635: Inappropriate implementation in Downloads
* Low CVE-2025-13636: Inappropriate implementation in Split View
* Low CVE-2025-13637: Inappropriate implementation in Downloads
* Low CVE-2025-13638: Use after free in Media Stream
* Low CVE-2025-13639: Inappropriate implementation in WebRTC
* Low CVE-2025-13640: Inappropriate implementation in Passwords");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~143.0.10^chromium143.0.7499.146~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~143.0.10^chromium143.0.7499.146~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~143.0.10^chromium143.0.7499.146~1.fc43", rls:"FC43"))) {
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

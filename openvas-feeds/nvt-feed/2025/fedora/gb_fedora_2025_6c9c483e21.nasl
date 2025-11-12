# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.69999948310121");
  script_cve_id("CVE-2025-10890", "CVE-2025-10891", "CVE-2025-10892", "CVE-2025-11205", "CVE-2025-11206", "CVE-2025-11207", "CVE-2025-11208", "CVE-2025-11209", "CVE-2025-11210", "CVE-2025-11211", "CVE-2025-11212", "CVE-2025-11213", "CVE-2025-11215", "CVE-2025-11216", "CVE-2025-11219", "CVE-2025-11458", "CVE-2025-11460", "CVE-2025-11756", "CVE-2025-12036");
  script_tag(name:"creation_date", value:"2025-11-11 04:07:18 +0000 (Tue, 11 Nov 2025)");
  script_version("2025-11-11T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-11 05:40:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-25 15:55:41 +0000 (Thu, 25 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-6c9c483e21)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6c9c483e21");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6c9c483e21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2025-6c9c483e21 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 141.0.7390.122

 * High CVE-2025-12036 chromium: Inappropriate implementation in V8
 * High CVE-2025-11756: Use after free in Safe Browsing
 * High CVE-2025-11458: Heap buffer overflow in Sync
 * High CVE-2025-11460: Use after free in Storage
 * Medium CVE-2025-11211: Out of bounds read in WebCodecs
 * High CVE-2025-11205: Heap buffer overflow in WebGPU
 * High CVE-2025-11206: Heap buffer overflow in Video
 * Medium CVE-2025-11207: Side-channel information leakage in Storage
 * Medium CVE-2025-11208: Inappropriate implementation in Media
 * Medium CVE-2025-11209: Inappropriate implementation in Omnibox
 * Medium CVE-2025-11210: Side-channel information leakage in Tab
 * Medium CVE-2025-11211: Out of bounds read in Media
 * Medium CVE-2025-11212: Inappropriate implementation in Media
 * Medium CVE-2025-11213: Inappropriate implementation in Omnibox
 * Medium CVE-2025-11215: Off by one error in V8
 * Low CVE-2025-11216: Inappropriate implementation in Storage
 * Low CVE-2025-11219: Use after free in V8
 * CVE-2025-10890: Side-channel information leakage in V8
 * CVE-2025-10891: Integer overflow in V8
 * CVE-2025-10892: Integer overflow in V8");

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

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~141.0.11^chromium141.0.7390.122~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~141.0.11^chromium141.0.7390.122~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~141.0.11^chromium141.0.7390.122~1.fc43", rls:"FC43"))) {
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

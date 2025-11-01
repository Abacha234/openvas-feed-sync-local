# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.51029799639897697");
  script_cve_id("CVE-2025-10200", "CVE-2025-10201", "CVE-2025-10500", "CVE-2025-10501", "CVE-2025-10502", "CVE-2025-10585", "CVE-2025-10890", "CVE-2025-10891", "CVE-2025-10892", "CVE-2025-9864", "CVE-2025-9865", "CVE-2025-9866", "CVE-2025-9867");
  script_tag(name:"creation_date", value:"2025-10-13 04:05:45 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-30 13:46:06 +0000 (Tue, 30 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-5fac63ba6a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5fac63ba6a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5fac63ba6a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2396308");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2025-5fac63ba6a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 140.1.15^chromium140.0.7339.207 (rhbz#2396308)

 * CVE-2025-10890: Side-channel information leakage in V8
 * CVE-2025-10891: Integer overflow in V8
 * CVE-2025-10892: Integer overflow in V8
 * CVE-2025-10585: Type Confusion in V8
 * CVE-2025-10500: Use after free in Dawn
 * CVE-2025-10501: Use after free in WebRTC
 * CVE-2025-10502: Heap buffer overflow in ANGLE
 * CVE-2025-10200: Use after free in Serviceworker
 * CVE-2025-10201: Inappropriate implementation in Mojo
 * CVE-2025-9864: Use after free in V8
 * CVE-2025-9865: Inappropriate implementation in Toolbar
 * CVE-2025-9866: Inappropriate implementation in Extensions
 * CVE-2025-9867: Inappropriate implementation in Downloads");

  script_tag(name:"affected", value:"'cef' package(s) on Fedora 42.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~140.1.15^chromium140.0.7339.207~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~140.1.15^chromium140.0.7339.207~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~140.1.15^chromium140.0.7339.207~3.fc42", rls:"FC42"))) {
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

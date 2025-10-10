# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.2100410091980097");
  script_cve_id("CVE-2025-11205", "CVE-2025-11206", "CVE-2025-11207", "CVE-2025-11208", "CVE-2025-11209", "CVE-2025-11210", "CVE-2025-11211", "CVE-2025-11212", "CVE-2025-11213", "CVE-2025-11215", "CVE-2025-11216", "CVE-2025-11219");
  script_tag(name:"creation_date", value:"2025-10-09 04:05:22 +0000 (Thu, 09 Oct 2025)");
  script_version("2025-10-09T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-2d4d91b00a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-2d4d91b00a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-2d4d91b00a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381730");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400095");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-2d4d91b00a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 141.0.7390.54

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
 * Low CVE-2025-11219: Use after free in V8");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui-debuginfo", rpm:"chromium-qt5-ui-debuginfo~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~141.0.7390.54~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui-debuginfo", rpm:"chromium-qt6-ui-debuginfo~141.0.7390.54~1.fc41", rls:"FC41"))) {
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

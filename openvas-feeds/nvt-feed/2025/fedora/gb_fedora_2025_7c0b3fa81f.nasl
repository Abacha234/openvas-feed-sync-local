# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.79909831029781102");
  script_cve_id("CVE-2025-12036", "CVE-2025-12428", "CVE-2025-12429", "CVE-2025-12430", "CVE-2025-12431", "CVE-2025-12432", "CVE-2025-12433", "CVE-2025-12434", "CVE-2025-12435", "CVE-2025-12436", "CVE-2025-12437", "CVE-2025-12438", "CVE-2025-12439", "CVE-2025-12440", "CVE-2025-12441", "CVE-2025-12443", "CVE-2025-12444", "CVE-2025-12445", "CVE-2025-12446", "CVE-2025-12447");
  script_tag(name:"creation_date", value:"2025-11-10 04:10:19 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-7c0b3fa81f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-7c0b3fa81f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-7c0b3fa81f");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-7c0b3fa81f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 142.0.7444.59

 * High CVE-2025-12428: Type Confusion in V8
 * High CVE-2025-12429: Inappropriate implementation in V8
 * High CVE-2025-12430: Object lifecycle issue in Media
 * High CVE-2025-12431: Inappropriate implementation in Extensions
 * High CVE-2025-12432: Race in V8
 * High CVE-2025-12433: Inappropriate implementation in V8
 * High CVE-2025-12036: Inappropriate implementation in V8
 * Medium CVE-2025-12434: Race in Storage
 * Medium CVE-2025-12435: Incorrect security UI in Omnibox
 * Medium CVE-2025-12436: Policy bypass in Extensions
 * Medium CVE-2025-12437: Use after free in PageInfo
 * Medium CVE-2025-12438: Use after free in Ozone
 * Medium CVE-2025-12439: Inappropriate implementation in App-Bound Encryption
 * Low CVE-2025-12440: Inappropriate implementation in Autofill
 * Medium CVE-2025-12441: Out of bounds read in V8
 * Medium CVE-2025-12443: Out of bounds read in WebXR
 * Low CVE-2025-12444: Incorrect security UI in Fullscreen UI
 * Low CVE-2025-12445: Policy bypass in Extensions
 * Low CVE-2025-12446: Incorrect security UI in SplitView
 * Low CVE-2025-12447: Incorrect security UI in Omnibox");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui-debuginfo", rpm:"chromium-qt5-ui-debuginfo~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~142.0.7444.59~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui-debuginfo", rpm:"chromium-qt6-ui-debuginfo~142.0.7444.59~1.fc42", rls:"FC42"))) {
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

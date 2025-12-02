# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.60410102999772");
  script_cve_id("CVE-2025-12036", "CVE-2025-12428", "CVE-2025-12429", "CVE-2025-12430", "CVE-2025-12431", "CVE-2025-12432", "CVE-2025-12433", "CVE-2025-12434", "CVE-2025-12435", "CVE-2025-12436", "CVE-2025-12437", "CVE-2025-12438", "CVE-2025-12439", "CVE-2025-12440", "CVE-2025-12441", "CVE-2025-12443", "CVE-2025-12444", "CVE-2025-12445", "CVE-2025-12446", "CVE-2025-12447", "CVE-2025-12725", "CVE-2025-12726", "CVE-2025-12727", "CVE-2025-12728", "CVE-2025-12729");
  script_tag(name:"creation_date", value:"2025-12-01 04:25:36 +0000 (Mon, 01 Dec 2025)");
  script_version("2025-12-01T05:45:26+0000");
  script_tag(name:"last_modification", value:"2025-12-01 05:45:26 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-604e02ca72)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-604e02ca72");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-604e02ca72");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cef' package(s) announced via the FEDORA-2025-604e02ca72 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 142.0.7444.162

* High CVE-2025-12725: Out of bounds write in WebGPU
* High CVE-2025-12726: Inappropriate implementation in Views
* High CVE-2025-12727: Inappropriate implementation in V8
* Medium CVE-2025-12728: Inappropriate implementation in Omnibox
* Medium CVE-2025-12729: Inappropriate implementation in Omnibox
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

  if(!isnull(res = isrpmvuln(pkg:"cef", rpm:"cef~142.0.14^chromium142.0.7444.162~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-debuginfo", rpm:"cef-debuginfo~142.0.14^chromium142.0.7444.162~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cef-devel", rpm:"cef-devel~142.0.14^chromium142.0.7444.162~1.fc43", rls:"FC43"))) {
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

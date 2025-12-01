# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0313");
  script_cve_id("CVE-2024-23271", "CVE-2024-27808", "CVE-2024-27820", "CVE-2024-27833", "CVE-2024-27856", "CVE-2024-40866", "CVE-2024-44185", "CVE-2024-44187", "CVE-2024-44192", "CVE-2024-44244", "CVE-2024-44296", "CVE-2024-44308", "CVE-2024-54467", "CVE-2024-54479", "CVE-2024-54502", "CVE-2024-54505", "CVE-2024-54534", "CVE-2024-54543", "CVE-2024-54551", "CVE-2025-24143", "CVE-2025-24150", "CVE-2025-24158", "CVE-2025-24162", "CVE-2025-24189", "CVE-2025-24201", "CVE-2025-24208", "CVE-2025-24209", "CVE-2025-24213", "CVE-2025-24216", "CVE-2025-24223", "CVE-2025-24264", "CVE-2025-30427", "CVE-2025-31204", "CVE-2025-31205", "CVE-2025-31206", "CVE-2025-31215", "CVE-2025-31257", "CVE-2025-31273", "CVE-2025-31278", "CVE-2025-43211", "CVE-2025-43212", "CVE-2025-43216", "CVE-2025-43227", "CVE-2025-43228", "CVE-2025-43240", "CVE-2025-43265", "CVE-2025-43272", "CVE-2025-43342", "CVE-2025-43343", "CVE-2025-43356", "CVE-2025-43368", "CVE-2025-6558");
  script_tag(name:"creation_date", value:"2025-11-26 04:12:52 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-14 13:52:54 +0000 (Fri, 14 Nov 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0313");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0313.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34747");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/05/14/webkitgtk2.48.2-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/05/28/webkitgtk2.48.3-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/07/31/webkitgtk2.49.4-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/08/01/webkitgtk2.48.5-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/09/03/webkitgtk2.48.6-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/09/17/webkitgtk2.50.0-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2025/10/10/webkitgtk2.50.1-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2025-0005.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2025-0006.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2025-0007.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2025-0313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"We are updating webkit2 to version 2.50.1 that has many security fixes
since our current version.
Please see the links for additional information");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.1", rpm:"lib64javascriptcore-gir4.1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir6.0", rpm:"lib64javascriptcore-gir6.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.1_0", rpm:"lib64javascriptcoregtk4.1_0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk6.0_1", rpm:"lib64javascriptcoregtk6.0_1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.1", rpm:"lib64webkit2gtk-gir4.1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0-devel", rpm:"lib64webkit2gtk4.0-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1-devel", rpm:"lib64webkit2gtk4.1-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.1_0", rpm:"lib64webkit2gtk4.1_0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk-gir6.0", rpm:"lib64webkitgtk-gir6.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0-devel", rpm:"lib64webkitgtk6.0-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk6.0_4", rpm:"lib64webkitgtk6.0_4~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.1", rpm:"libjavascriptcore-gir4.1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir6.0", rpm:"libjavascriptcore-gir6.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.1_0", rpm:"libjavascriptcoregtk4.1_0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk6.0_1", rpm:"libjavascriptcoregtk6.0_1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.1", rpm:"libwebkit2gtk-gir4.1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0-devel", rpm:"libwebkit2gtk4.0-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1-devel", rpm:"libwebkit2gtk4.1-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.1_0", rpm:"libwebkit2gtk4.1_0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-gir6.0", rpm:"libwebkitgtk-gir6.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0-devel", rpm:"libwebkitgtk6.0-devel~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk6.0_4", rpm:"libwebkitgtk6.0_4~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-driver", rpm:"webkit2-driver~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0", rpm:"webkit2gtk4.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.0-jsc", rpm:"webkit2gtk4.0-jsc~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1", rpm:"webkit2gtk4.1~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4.1-jsc", rpm:"webkit2gtk4.1-jsc~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0", rpm:"webkitgtk6.0~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk6.0-jsc", rpm:"webkitgtk6.0-jsc~2.50.1~1.2.mga9", rls:"MAGEIA9"))) {
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

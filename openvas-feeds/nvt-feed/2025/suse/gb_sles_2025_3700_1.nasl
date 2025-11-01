# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3700.1");
  script_cve_id("CVE-2025-43272", "CVE-2025-43342", "CVE-2025-43343", "CVE-2025-43356", "CVE-2025-43368");
  script_tag(name:"creation_date", value:"2025-10-23 04:11:55 +0000 (Thu, 23 Oct 2025)");
  script_version("2025-10-24T05:39:31+0000");
  script_tag(name:"last_modification", value:"2025-10-24 05:39:31 +0000 (Fri, 24 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3700-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3700-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253700-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251975");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042239.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:3700-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

 - CVE-2025-43343: improved memory handling in web content processing to prevent process crash (bsc#1251975)
 - CVE-2025-43272: improved memory handling to prevent unexpected process crash (bsc#1250439)
 - CVE-2025-43342: correctness issue was addressed with improved checks to prevent unexcepted process crash (bsc#1250440)
 - CVE-2025-43356: improved handling of caches to prevent sensor access without consent (bsc#1250441)
 - CVE-2025-43368: improved memory management to prevent a use-after-free (bsc#1250442)");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.50.1~150400.4.127.3", rls:"SLES15.0SP5"))) {
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

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4433.1");
  script_tag(name:"creation_date", value:"2025-12-19 04:19:24 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4433-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4433-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254433-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023582.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2025:4433-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

* Update to 3.9.25:
- Security
 - gh-137836: Add support of the 'plaintext' element, RAWTEXT
 elements 'xmp', 'iframe', 'noembed' and 'noframes', and
 optionally RAWTEXT element 'noscript' in
 html.parser.HTMLParser.
 - gh-136063: email.message: ensure linear complexity for
 legacy HTTP parameters parsing. Patch by Benedikt Tran.
- Library
 - gh-98793: Fix argument typechecks in
 _overlapped.WSAConnect() and
 _overlapped.Overlapped.WSASendTo() functions. bpo-44817:
 Ignore WinError 53 (ERROR_BAD_NETPATH), 65
 (ERROR_NETWORK_ACCESS_DENIED) and 161 (ERROR_BAD_PATHNAME)
 when using ntpath.realpath().
- Core and Builtins
 - gh-120384: Fix an array out of bounds crash in
 list_ass_subscript, which could be invoked via some
 specificly tailored input: including concurrent
 modification of a list object, where one thread assigns
 a slice and another clears it.
 - gh-120298: Fix use-after free in list_richcompare_impl
 which can be invoked via some specificly tailored evil
 input.");

  script_tag(name:"affected", value:"'python39' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-32bit", rpm:"libpython3_9-1_0-32bit~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-32bit", rpm:"python39-32bit~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-32bit", rpm:"python39-base-32bit~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc", rpm:"python39-doc~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-doc-devhelp", rpm:"python39-doc-devhelp~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-testsuite", rpm:"python39-testsuite~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.25~150300.4.87.1", rls:"openSUSELeap15.6"))) {
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

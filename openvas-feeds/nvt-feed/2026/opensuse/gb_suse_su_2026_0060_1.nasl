# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0060.1");
  script_cve_id("CVE-2025-67873", "CVE-2025-68114");
  script_tag(name:"creation_date", value:"2026-01-09 12:05:46 +0000 (Fri, 09 Jan 2026)");
  script_version("2026-01-09T15:42:56+0000");
  script_tag(name:"last_modification", value:"2026-01-09 15:42:56 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-02 18:33:09 +0000 (Fri, 02 Jan 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0060-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260060-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255310");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023700.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'capstone' package(s) announced via the SUSE-SU-2026:0060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for capstone fixes the following issues:

Security issues fixed:

- CVE-2025-67873: missing bounds check on user-provided skipdata callback can lead to a heap buffer overflow
 (bsc#1255309).
- CVE-2025-68114: unchecked `vsnprintf` return value can lead to a stack buffer overflow (bsc#1255310).

Other updates and bugfixes:

- Enable static library, and add `libcapstone-devel-static` subpackage.");

  script_tag(name:"affected", value:"'capstone' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"capstone", rpm:"capstone~4.0.2~150500.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"capstone-doc", rpm:"capstone-doc~4.0.2~150500.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcapstone-devel", rpm:"libcapstone-devel~4.0.2~150500.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcapstone4", rpm:"libcapstone4~4.0.2~150500.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-capstone", rpm:"python3-capstone~4.0.2~150500.3.3.1", rls:"openSUSELeap15.6"))) {
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

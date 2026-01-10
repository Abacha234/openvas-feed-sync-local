# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0044.1");
  script_cve_id("CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492", "CVE-2024-50602");
  script_tag(name:"creation_date", value:"2026-01-08 14:10:32 +0000 (Thu, 08 Jan 2026)");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0044-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0044-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260044-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232602");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023693.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozjs60' package(s) announced via the SUSE-SU-2026:0044-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozjs60 fixes the following issues:

- CVE-2024-45492: embedded expat: detect integer overflow in function nextScaffoldPart (bsc#1230038)
- CVE-2024-45491: embedded expat: detect integer overflow in dtdCopy (bsc#1230037)
- CVE-2024-45490: embedded expat: reject negative len for XML_ParseBuffer (bsc#1230036)
- CVE-2024-50602: libexpat: DoS via XML_ResumeParser (bsc#1232602)");

  script_tag(name:"affected", value:"'mozjs60' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-60", rpm:"libmozjs-60~60.9.0~150200.6.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs60", rpm:"mozjs60~60.9.0~150200.6.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs60-devel", rpm:"mozjs60-devel~60.9.0~150200.6.8.1", rls:"openSUSELeap15.6"))) {
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

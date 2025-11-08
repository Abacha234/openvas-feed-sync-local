# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.3946.1");
  script_cve_id("CVE-2023-39327");
  script_tag(name:"creation_date", value:"2025-11-06 14:12:56 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-13 03:15:09 +0000 (Sat, 13 Jul 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:3946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3946-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253946-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250467");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023156.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg' package(s) announced via the SUSE-SU-2025:3946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg fixes the following issues:

- CVE-2023-39327: Fixed that malicious files can cause a large loop that continuously prints warning messages on the terminal (bsc#1227410).

Other bug fixes:

- Ensure no bundled libraries are used (bsc#1250467).");

  script_tag(name:"affected", value:"'openjpeg' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1", rpm:"libopenjpeg1~1.5.2~150000.4.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-32bit", rpm:"libopenjpeg1-32bit~1.5.2~150000.4.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.5.2~150000.4.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.5.2~150000.4.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel-32bit", rpm:"openjpeg-devel-32bit~1.5.2~150000.4.15.1", rls:"openSUSELeap15.6"))) {
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

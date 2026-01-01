# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4390.1");
  script_cve_id("CVE-2025-66453");
  script_tag(name:"creation_date", value:"2025-12-15 04:31:40 +0000 (Mon, 15 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4390-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4390-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254390-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254481");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023537.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rhino' package(s) announced via the SUSE-SU-2025:4390-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rhino fixes the following issues:

Update to version 1.7.15.1.

Security issues fixed:

- CVE-2025-66453: high CPU consumption when processing specific numbers via the `toFixed()` function (bsc#1254481).

Other changes and issues fixed:

- Version 1.7.15:
 * Basic support for 'rest parameters'.
 * Improvements in Unicode support.
 * 'Symbol.species' implemented in many places.
 * More correct property ordering in many places.
 * Miscellaneous improvements and bug fixes.");

  script_tag(name:"affected", value:"'rhino' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"rhino", rpm:"rhino~1.7.15.1~150200.12.7.1", rls:"SLES15.0SP6"))) {
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

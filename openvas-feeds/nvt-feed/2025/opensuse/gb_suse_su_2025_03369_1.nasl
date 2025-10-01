# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03369.1");
  script_cve_id("CVE-2025-8114", "CVE-2025-8277");
  script_tag(name:"creation_date", value:"2025-09-29 09:12:52 +0000 (Mon, 29 Sep 2025)");
  script_version("2025-09-29T10:42:25+0000");
  script_tag(name:"last_modification", value:"2025-09-29 10:42:25 +0000 (Mon, 29 Sep 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-24 15:15:27 +0000 (Thu, 24 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03369-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503369-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249375");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041852.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the SUSE-SU-2025:03369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh fixes the following issues:

- CVE-2025-8277: memory exhaustion leading to client-side DoS due to improper memory management when KEX process is
 repeated with incorrect guesses (bsc#1249375).
- CVE-2025-8114: NULL pointer dereference when an allocation error happens during the calculation of the KEX session ID
 (bsc#1246974).");

  script_tag(name:"affected", value:"'libssh' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.9.8~150600.11.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.8~150600.11.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.8~150600.11.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4-32bit", rpm:"libssh4-32bit~0.9.8~150600.11.6.1", rls:"openSUSELeap15.6"))) {
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

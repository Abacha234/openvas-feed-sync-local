# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.3794.1");
  script_tag(name:"creation_date", value:"2025-10-27 04:12:26 +0000 (Mon, 27 Oct 2025)");
  script_version("2025-10-28T05:40:26+0000");
  script_tag(name:"last_modification", value:"2025-10-28 05:40:26 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:3794-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3794-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253794-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246544");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042294.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony' package(s) announced via the SUSE-SU-2025:3794-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chrony fixes the following issues:

- Race condition during socket creation by chronyc allows privilege escalation from user chrony to root (bsc#1246544).

This update also ships chrony-pool-empty to SLE Micro 5.x (jsc#SMO-587)");

  script_tag(name:"affected", value:"'chrony' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~4.1~150400.21.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-pool-empty", rpm:"chrony-pool-empty~4.1~150400.21.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-pool-openSUSE", rpm:"chrony-pool-openSUSE~4.1~150400.21.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-pool-suse", rpm:"chrony-pool-suse~4.1~150400.21.8.1", rls:"openSUSELeap15.6"))) {
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

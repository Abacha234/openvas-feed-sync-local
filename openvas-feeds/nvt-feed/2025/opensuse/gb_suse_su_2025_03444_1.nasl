# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03444.1");
  script_cve_id("CVE-2025-23419", "CVE-2025-53859");
  script_tag(name:"creation_date", value:"2025-10-03 04:06:43 +0000 (Fri, 03 Oct 2025)");
  script_version("2025-10-03T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-10-03 15:40:40 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03444-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503444-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248070");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/041989.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the SUSE-SU-2025:03444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nginx fixes the following issues:

- CVE-2025-53859: the server side may leak arbitrary bytes during the NGINX SMTP authentication process (bsc#1248070).
- CVE-2025-23419: session resumption can bypass client certificate authentication requirements using TLSv1.3 (bsc#1236851).");

  script_tag(name:"affected", value:"'nginx' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.21.5~150600.10.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-source", rpm:"nginx-source~1.21.5~150600.10.12.1", rls:"openSUSELeap15.6"))) {
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

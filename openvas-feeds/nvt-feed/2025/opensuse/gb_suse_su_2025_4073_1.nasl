# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4073.1");
  script_cve_id("CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881");
  script_tag(name:"creation_date", value:"2025-11-13 13:58:42 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4073-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4073-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254073-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252232");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.3.0");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.3.1");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.3.2");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/releases/tag/v1.3.3");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023265.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'runc' package(s) announced via the SUSE-SU-2025:4073-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for runc fixes the following issues:

Update to runc v1.3.3. Upstream changelog is available from

 <[link moved to references]>. bsc#1252232

 * CVE-2025-31133
 * CVE-2025-52565
 * CVE-2025-52881

Update to runc v1.3.2. Upstream changelog is available from

<[link moved to references]> bsc#1252110

 - Includes an important fix for the CPUSet translation for cgroupv2.

Update to runc v1.3.1. Upstream changelog is available from

<[link moved to references]>

Update to runc v1.3.0. Upstream changelog is available from

<[link moved to references]>");

  script_tag(name:"affected", value:"'runc' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"runc", rpm:"runc~1.3.3~150000.85.1", rls:"openSUSELeap15.6"))) {
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

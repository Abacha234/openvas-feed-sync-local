# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4532.1");
  script_cve_id("CVE-2019-14857", "CVE-2019-20479", "CVE-2021-32785", "CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792", "CVE-2021-39191", "CVE-2022-23527", "CVE-2023-28625", "CVE-2024-24814", "CVE-2025-31492", "CVE-2025-3891");
  script_tag(name:"creation_date", value:"2025-12-31 04:19:38 +0000 (Wed, 31 Dec 2025)");
  script_version("2026-01-02T15:40:50+0000");
  script_tag(name:"last_modification", value:"2026-01-02 15:40:50 +0000 (Fri, 02 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-12 19:36:31 +0000 (Mon, 12 May 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4532-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254532-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248806");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023659.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_auth_openidc' package(s) announced via the SUSE-SU-2025:4532-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_auth_openidc fixes the following issues:

- Update to 2.4.17.1 (bsc#1248806 / PED-14130).
- Remove many patches, as they've been merged upstream.");

  script_tag(name:"affected", value:"'apache2-mod_auth_openidc' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc", rpm:"apache2-mod_auth_openidc~2.4.17.1~150600.16.14.1", rls:"openSUSELeap15.6"))) {
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

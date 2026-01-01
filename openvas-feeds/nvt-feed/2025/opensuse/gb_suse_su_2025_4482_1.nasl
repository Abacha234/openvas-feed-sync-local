# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4482.1");
  script_cve_id("CVE-2025-11065", "CVE-2025-3415", "CVE-2025-47911", "CVE-2025-58190", "CVE-2025-6023", "CVE-2025-6197", "CVE-2025-64751");
  script_tag(name:"creation_date", value:"2025-12-19 14:54:15 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4482-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254482-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254113");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023614.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2025:4482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

grafana was updated from version 11.5.5 to 11.5.10:

- Security issues fixed:

 * CVE-2025-64751: Dropped experimental implementation of authorization Zanzana server/client (version 11.5.10)
 (bsc#1254113)
 * CVE-2025-47911: Fixed parsing HTML documents (version 11.5.10) (bsc#1251454)
 * CVE-2025-58190: Fixed excessive memory consumption (version 11.5.10) (bsc#1251657)
 * CVE-2025-11065: Fixed sensitive information leak in logs (version 11.5.9) (bsc#1250616)
 * CVE-2025-6023: Fixed cross-site-scripting via scripted dashboards (version 11.5.7) (bsc#1246735)
 * CVE-2025-6197: Fixed open redirect in organization switching (version 11.5.7) (bsc#1246736)
 * CVE-2025-3415: Fixed exposure of DingDing alerting integration URL to Viewer level users (version 11.5.6)
 (bsc#1245302)

- Other changes, new features and bugs fixed:

 * Version 11.5.10:
 + Use forked wire from Grafana repository instead of external package (jsc#PED-14178)
 + Auth: Fix render user OAuth passthrough.
 + LDAP Authentication: Fix URL to propagate username context as parameter.
 + Plugins: Dependencies do not inherit parent URL for preinstall.

 * Version 11.5.9:
 + Auditing: Document new options for recording datasource query request/response body.
 + Login: Fixed redirection after login when Grafana is served from subpath.

 * Version 11.5.7:
 + Azure: Fixed legend formatting and resource name determination in template variable queries.");

  script_tag(name:"affected", value:"'grafana' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~11.5.10~150200.3.80.1", rls:"openSUSELeap15.6"))) {
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

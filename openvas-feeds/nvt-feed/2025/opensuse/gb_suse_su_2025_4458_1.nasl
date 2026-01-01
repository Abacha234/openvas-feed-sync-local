# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4458.1");
  script_cve_id("CVE-2025-11065", "CVE-2025-3415", "CVE-2025-47911", "CVE-2025-58190", "CVE-2025-6023", "CVE-2025-6197", "CVE-2025-64751");
  script_tag(name:"creation_date", value:"2025-12-19 14:54:15 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4458-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254458-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252100");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023628.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security update 5.0.6 for Multi-Linux Manager Client Tools' package(s) announced via the SUSE-SU-2025:4458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

dracut-saltboot:

- Update to version 1.0.0
 * Reboot on salt key timeout (bsc#1237495)
 * Fixed parsing files with space in the name (bsc#1252100)

grafana was updated from version 11.5.5 to 11.5.10:

- Security issues fixed:

 * CVE-2025-47911: Fix parsing HTML documents (bsc#1251454)
 * CVE-2025-58190: Fix excessive memory consumption (bsc#1251657)
 * CVE-2025-64751: Drop experimental implementation of authorization Zanzana server/client
 (bsc#1254113)
 * CVE-2025-11065: Fixed sensitive information leak in logs (version 11.5.9) (bsc#1250616)
 * CVE-2025-6023: Fixed cross-site-scripting via scripted dashboards (version 11.5.7) (bsc#1246735)
 * CVE-2025-6197: Fixed open redirect in organization switching (version 11.5.7) (bsc#1246736)
 * CVE-2025-3415: Fixed exposure of DingDing alerting integration URL to Viewer level users (version 11.5.6)
 (bsc#1245302)

- Other changes, new features and bugs fixed:

 * Version 11.5.10:
 + Update to Go 1.25
 + Update to golang.org/x/net v0.45.0
 + Auth: Fix render user OAuth passthrough
 + LDAP Authentication: Fix URL to propagate username context as parameter

 * Version 11.5.9:
 + Auditing: Document new options for recording datasource query request/response body.
 + Login: Fixed redirection after login when Grafana is served from subpath.

 * Version 11.5.7:
 + Azure: Fixed legend formatting and resource name determination in template variable queries.

mgr-push:

- Version 5.0.3-0
 * Fixed syntax error in changelog

rhnlib:

- Version 5.0.6-0
 * Use more secure defusedxml parser (bsc#1227577)

spacecmd:

- Version 5.0.14-0
 * Fixed installation of python lib files on Ubuntu 24.04 (bsc#1246586)
 * Use JSON instead of pickle for spacecmd cache (bsc#1227579)
 * Make spacecmd to work with Python 3.12 and higher
 * Call print statements properly in Python 3

uyuni-tools:

- Version 0.1.37-0
 * Handle CA files with symlinks during migration (bsc#1251044)
 * Add a lowercase version of --logLevel (bsc#1243611)
 * Adjust traefik exposed configuration for chart v27+ (bsc#1247721)
 * Stop executing scripts in temporary folder (bsc#1243704)
 * Convert the traefik install time to local time (bsc#1251138)
 * Run smdba and reindex only during migration (bsc#1244534)
 * Support config: collect podman inspect for hub container (bsc#1245099)
 * Add --registry-host, --registry-user and --registry-password to pull images from an authenticate registry
 * Deprecate --registry
 * Use new dedicated path for Cobbler settings (bsc#1244027)
 * Migrate custom auto installation snippets (bsc#1246320)
 * Add SLE15SP7 to buildin productmap
 * Fix loading product map from mgradm configuration file (bsc#1246068)
 * Fix channel override for distro copy
 * Do not use sudo when running as a root user (bsc#1246882)
 * Do not require backups to be at the same location for restoring (bsc#1246906)
 * Check for restorecon ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Security update 5.0.6 for Multi-Linux Manager Client Tools' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dracut-saltboot", rpm:"dracut-saltboot~1.0.0~150000.1.62.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~5.0.14~150000.3.139.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"supportutils-plugin-susemanager-client", rpm:"supportutils-plugin-susemanager-client~5.0.5~150000.3.30.1", rls:"openSUSELeap15.6"))) {
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

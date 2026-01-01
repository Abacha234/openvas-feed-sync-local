# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.4481.1");
  script_cve_id("CVE-2025-47908");
  script_tag(name:"creation_date", value:"2025-12-19 14:54:15 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:4481-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4481-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254481-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247748");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023615.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-alertmanager' package(s) announced via the SUSE-SU-2025:4481-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for golang-github-prometheus-alertmanager fixes the following issues:

- Update to version 0.28.1 (jsc#PED-13285):
 * Improved performance of inhibition rules when using Equal
 labels.
 * Improve the documentation on escaping in UTF-8 matchers.
 * Update alertmanager_config_hash metric help to document the
 hash is not cryptographically strong.
 * Fix panic in amtool when using --verbose.
 * Fix templating of channel field for Rocket.Chat.
 * Fix rocketchat_configs written as rocket_configs in docs.
 * Fix usage for --enable-feature flag.
 * Trim whitespace from OpsGenie API Key.
 * Fix Jira project template not rendered when searching for
 existing issues.
 * Fix subtle bug in JSON/YAML encoding of inhibition rules that
 would cause Equal labels to be omitted.
 * Fix header for slack_configs in docs.
 * Fix weight and wrap of Microsoft Teams notifications.
- Upgrade to version 0.28.0:
 * CVE-2025-47908: Bump github.com/rs/cors (bsc#1247748).
 * Templating errors in the SNS integration now return an error.
 * Adopt log/slog, drop go-kit/log.
 * Add a new Microsoft Teams integration based on Flows.
 * Add a new Rocket.Chat integration.
 * Add a new Jira integration.
 * Add support for GOMEMLIMIT, enable it via the feature flag
 --enable-feature=auto-gomemlimit.
 * Add support for GOMAXPROCS, enable it via the feature flag
 --enable-feature=auto-gomaxprocs.
 * Add support for limits of silences including the maximum number
 of active and pending silences, and the maximum size per
 silence (in bytes). You can use the flags
 --silences.max-silences and --silences.max-silence-size-bytes
 to set them accordingly.
 * Muted alerts now show whether they are suppressed or not in
 both the /api/v2/alerts endpoint and the Alertmanager UI.
- Upgrade to version 0.27.0:
 * API: Removal of all api/v1/ endpoints. These endpoints
 now log and return a deprecation message and respond with a
 status code of 410.
 * UTF-8 Support: Introduction of support for any UTF-8
 character as part of label names and matchers.
 * Discord Integration: Enforce max length in message.
 * Metrics: Introduced the experimental feature flag
 --enable-feature=receiver-name-in-metrics to include the
 receiver name.
 * Metrics: Introduced a new gauge named
 alertmanager_inhibition_rules that counts the number of
 configured inhibition rules.
 * Metrics: Introduced a new counter named
 alertmanager_alerts_supressed_total that tracks muted alerts,
 it contains a reason label to indicate the source of the mute.
 * Discord Integration: Introduced support for webhook_url_file.
 * Microsoft Teams Integration: Introduced support for
 webhook_url_file.
 * Microsoft Teams Integration: Add support for summary.
 * Metrics: Notification metrics now support two new values for
 the label reason, contextCanceled and contextDeadlineExceeded.
 * Email Integration: Contents of auth_password_file are now
 trimmed of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'golang-github-prometheus-alertmanager' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.28.1~150100.4.28.2", rls:"openSUSELeap15.6"))) {
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

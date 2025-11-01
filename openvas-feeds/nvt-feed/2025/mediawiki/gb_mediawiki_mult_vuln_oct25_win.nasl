# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124526");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-14 07:10:43 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-11173", "CVE-2025-11175", "CVE-2025-61634", "CVE-2025-61635",
                "CVE-2025-61636", "CVE-2025-61637", "CVE-2025-61638", "CVE-2025-61639",
                "CVE-2025-61640", "CVE-2025-61641", "CVE-2025-61642", "CVE-2025-61643",
                "CVE-2025-61645", "CVE-2025-61646", "CVE-2025-61648", "CVE-2025-61651",
                "CVE-2025-61652", "CVE-2025-61653", "CVE-2025-61654", "CVE-2025-61655",
                "CVE-2025-61656", "CVE-2025-61657", "CVE-2025-61658");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.39.14, 1.40.x < 1.43.4, 1.44.x < 1.44.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist / security relevant fixes have been
  applied:

  - T387478, CVE-2025-61634: REST: Set cache-control value of max-age=60 for redirects.

  - T394396, CVE-2025-61636: Escape rawElement $content.

  - T394856, CVE-2025-61637: Escape three system messages used by live preview.

  - T401099, CVE-2025-61638: Sanitize data-attributes / Sanitizer::validateAttributes data-XSS.

  - T280413, CVE-2025-61639: Use ManualLogEntry::getDeleted in ::getRecentChange.

  - T402075, CVE-2025-61640: Parse messages instead of inserting them as HTML.

  - T298690, CVE-2025-61641: api: Disable maxsize in QueryAllPages in miser mode.

  - T402313, CVE-2025-61642: Escape submit button label for Codex-based HTMLForms.

  - T403757, CVE-2025-61643: Don't send suppressed recent changes to RCFeeds.

  - T403761, CVE-2025-61645: Fix i18n XSS in CodexTablePager.

  - T398706, CVE-2025-61646: Prevent leaking hidden usernames in Watchlist/RecentChanges.

  - T403408, CVE-2025-61651: fix XSS in tempuser-expired-link-tooltip message.

  - T404805, CVE-2025-61658: Add config variable to exclude from GlobalContributions.

  - T402077, CVE-2025-61648: Escape system messages before inserting them as HTML.

  - T355073, CVE-2025-61635: ApiFancyCaptchaReload: Reuse badcaptcha rate limit.

  - T397580, CVE-2025-61652: In API check user read permissions before showing PageInfo.

  - T364910, T396248, CVE-2025-11175: DiscussionTools should use better regex.

  - T401862, T402094, CVE-2025-11173: Reauth for enabling 2FA can be bypassed by submitting a form.

  - T396951, No CVE: FreeOTP refuses to add MediaWiki's 2FA details, because 'token is unsafe'.

  - T397577, CVE-2025-61653: Add authorizeRead check for extracts endpoint.

  - T397497, CVE-2025-61654: Exclude deleted entries when counting thanks.

  - T395858, CVE-2025-61655: Properly escape and parse system messages.

  - T397232, CVE-2025-61656: Sanitize attributes unwrapped from data-ve-attributes.

  - T398636, CVE-2025-61657: Insert sticky header labels as text instead of HTML.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.39.14, 1.40.x prior to 1.43.4,
  and 1.44.x prior to 1.44.1.");

  script_tag(name:"solution", value:"Update to version 1.39.14, 1.43.4, 1.44.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/wikitech-l@lists.wikimedia.org/thread/6I6GV6OP27OB7CZS2JUQ5IC6XFXRHLNQ/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T280413");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T298690");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T355073");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T364910");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T387478");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T394396");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T394856");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T395858");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T396951");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T397232");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T397497");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T397577");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T397580");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T398636");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T398706");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T401099");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T401862");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T402075");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T402077");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T402313");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T403408");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T403757");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T403761");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T404805");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.39.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.40.0", test_version_up: "1.43.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.43.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.44.0", test_version_up: "1.44.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.44.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

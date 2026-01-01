# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125596");
  script_version("2025-12-17T05:46:28+0000");
  script_tag(name:"last_modification", value:"2025-12-17 05:46:28 +0000 (Wed, 17 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-16 14:06:10 +0000 (Tue, 16 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2025-67475", "CVE-2025-67476", "CVE-2025-67477", "CVE-2025-67478",
                "CVE-2025-67479", "CVE-2025-67480", "CVE-2025-67481", "CVE-2025-67482",
                "CVE-2025-67483", "CVE-2025-67484");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.39.16, 1.40.x < 1.43.6, 1.44.x < 1.44.3, 1.45.x < 1.45.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist / security relevant fixes have been
  applied:

  - T401987, T401995, CVE-2025-67484: Disable xslt option by default.

  - T406639, CVE-2025-67477: Escape word-separator message in Special:ApiSandbox.

  - T406664, CVE-2025-67475: Escape square brackets in autocomment links.

  - T405859, CVE-2025-67476: Do not use importers IP in case of external rev author.

  - T385403, CVE-2025-67478: Always escape commas in mail encoded-words.

  - T407131, CVE-2025-67479: Disallow underscore and wide underscore in data-*
  attribute names.

  - T401053, CVE-2025-67480: Check read permissions in ApiQueryRevisionsBase.

  - T409226, CVE-2025-67483: mediawiki.page.preview: Escape 'comma-separator' between
  multiple protection levels.

  - T251032, CVE-2025-67481: Disallow 'style' attribute in client-side messages (jqueryMsg).

  - T408135, CVE-2025-67482: Lua segfault in unpack().");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.39.16, 1.40.x prior to 1.43.6,
  1.44.x prior to 1.44.3 and 1.45.x prior to 1.45.1.");

  script_tag(name:"solution", value:"Update to version 1.39.16, 1.43.6, 1.44.3, 1.45.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/FOY6VXTBCCHIGYGSTQBPN3UFCL6CAX6Y/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T251032");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T385403");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T401053");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T401987");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T401995");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T405859");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T406639");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T406664");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T407131");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T408135");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T409226");

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

if (version_is_less(version: version, test_version: "1.39.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.40.0", test_version_up: "1.43.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.43.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.44.0", test_version_up: "1.44.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.44.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.45.0", test_version_up: "1.45.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.45.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

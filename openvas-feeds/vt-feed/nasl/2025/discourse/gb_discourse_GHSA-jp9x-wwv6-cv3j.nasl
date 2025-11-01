# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119213");
  script_version("2025-10-31T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-29 11:02:22 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-61598");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse Cache Poisoning Vulnerability (GHSA-jp9x-wwv6-cv3j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to a cache poisoning vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Default Cache-Control response header with value no-store,
  no-cache was missing from error responses. This may caused unintended caching of those responses
  by proxies potentially leading to cache poisoning attacks.");

  # nb: As of 10/2025 the advisory seems to have inconsistent info and e.g. lists "stable > 3.6.1"
  # as fixed while this should be "stable > 3.5.1" instead (see announcement topics). This has been
  # reported to the vendor accordingly.
  script_tag(name:"affected", value:"Discourse versions prior to 3.5.2 and 3.6.0.beta prior to
  3.6.0.beta2.");

  script_tag(name:"solution", value:"Update to version 3.5.2, 3.6.0.beta2 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jp9x-wwv6-cv3j");
  script_xref(name:"URL", value:"https://meta.discourse.org/t/3-5-2-security-and-maintenance-release/386388");
  script_xref(name:"URL", value:"https://meta.discourse.org/t/3-6-0-beta2-built-in-palette-editing-live-ai-translation-progress-and-better-wiki-tracking/386389");

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

if (version_is_less(version: version, test_version: "3.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.6.0.beta", test_version_up: "3.6.0.beta2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.0.beta2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

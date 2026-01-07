# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156080");
  script_version("2026-01-06T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-06 05:47:51 +0000 (Tue, 06 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-05 03:33:48 +0000 (Mon, 05 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-64528");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2025.11.x < 2025.11.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Even with enable_names disabled if an attacker knows a part of
  a user name, they can find the user and their full name via UI or API.");

  script_tag(name:"affected", value:"Discourse version 2025.11.0.");

  script_tag(name:"solution", value:"Update to version 2025.11.1 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-c59w-jwx7-34v4");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2025.11.0", test_version_up: "2025.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2025.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

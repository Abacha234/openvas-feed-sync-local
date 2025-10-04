# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155530");
  script_version("2025-10-03T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-10-03 05:38:37 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-02 05:18:47 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2025-58054", "CVE-2025-58055", "CVE-2025-59337");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.6.x < 3.6.0.beta2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-58054: XSS when quoting chat messages via channel title and thread title in RTE

  - CVE-2025-58055: Insecure Direct Object Reference via AI Suggestions

  - CVE-2025-59337: Backup restore meta-command injection leading to cross-site data access in
  multisite environments");

  script_tag(name:"affected", value:"Discourse versions 3.6.x prior to 3.6.0.beta2.");

  script_tag(name:"solution", value:"Update to version 3.6.0.beta2 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7p47-8m82-m2vf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-32v2-x274-vfhr");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7xjr-4f4g-9887");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.6.0.beta", test_version_up: "3.6.0.beta2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.0.beta2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

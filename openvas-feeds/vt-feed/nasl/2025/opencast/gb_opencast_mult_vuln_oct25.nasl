# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136131");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-09 09:03:23 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-09 16:00:05 +0000 (Thu, 09 Oct 2025)");

  script_cve_id("CVE-2025-61788", "CVE-2025-61906");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Opencast < 17.8, 18.x < 18.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-61788: A cross-site scripting (XSS) vulnerability

  - CVE-2025-61906: An information disclosure vulnerability");

  script_tag(name:"impact", value:"The attacker may (i) modify the site or execute actions in the
  name of the user, or (ii) leak internal media.");

  script_tag(name:"affected", value:"Opencast prior to version 17.8 and 18.x prior to 18.2.");

  script_tag(name:"solution", value:"Update to version 17.8, 18.2 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-x6vw-p693-jjhv");
  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-m2vg-rmq6-p62r");

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

if (version_is_less(version: version, test_version: "17.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125487");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 10:22:35 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-20210");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station XMR Mining Vulnerability (NAS-201705-04)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/photostation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to a vulnerability related to XMR
  mining programs.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Photo Station contains a vulnerability related to XMR mining
  programs that was identified by internal research.");

  script_tag(name:"affected", value:"QNAP Photo Station builds prior to version 5.2.7 and 5.3.x
  prior to  5.4.1.");

  script_tag(name:"solution", value:"Update to version 5.2.7, 5.4.1 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-in/security-advisory/nas-201705-04");

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

if (version_is_less(version: version, test_version: "5.2.7") ) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3", test_version_up: "5.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

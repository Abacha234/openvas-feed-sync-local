# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125578");
  script_version("2025-12-10T05:45:47+0000");
  script_tag(name:"last_modification", value:"2025-12-10 05:45:47 +0000 (Wed, 10 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-09 09:34:01 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2025-27844");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.15.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ownCloud allows access to internal app configuration data where
  the key is prefixed with remote and public via the HTTP API. These are internal configuration
  settings which should not be exposed via the network.");

  script_tag(name:"affected", value:"ownCloud prior to version 10.15.1.");

  script_tag(name:"solution", value:"Update to version 10.15.1 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/changelog/server/#changelog-for-owncloud-core-10151-2025-03-03");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/pull/41355");

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

if (version_is_less(version: version, test_version: "10.15.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.15.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125579");
  script_version("2025-12-16T05:46:07+0000");
  script_tag(name:"last_modification", value:"2025-12-16 05:46:07 +0000 (Tue, 16 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-15 12:11:45 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2025-64011");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server IDOR Vulnerability (GHSA-h6j9-6xjq-44c4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an Insecure Direct Object
  Reference (IDOR) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nextcloud Server is vulnerable to an IDOR in the
  /core/preview endpoint. Any authenticated user can access previews of arbitrary files belonging
  to other users by manipulating the fileId parameter.");

  script_tag(name:"affected", value:"Nextcloud Server prior to version 31.0.9.1.");

  script_tag(name:"solution", value:"Update to version 31.0.9.1 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-h6j9-6xjq-44c4");
  script_xref(name:"URL", value:"https://gist.github.com/tarekramm/586dfe2d113fedfee6d71182570fc090");

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

if (version_is_less(version: version, test_version: "31.0.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "31.0.9.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

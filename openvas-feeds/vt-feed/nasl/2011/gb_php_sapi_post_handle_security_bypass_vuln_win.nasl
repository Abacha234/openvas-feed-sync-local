# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902606");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2011-2202");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.7 Security Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'SAPI_POST_HANDLER_FUNC()'
  function in rfc1867.c when handling files via a 'multipart/form-data' POST request. which allows
  attacker to bypass security restriction.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to delete
  files from the root directory, which may aid in further attacks.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.7.");

  script_tag(name:"solution", value:"Update to version 5.3.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48259");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025659");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67999");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=312103");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

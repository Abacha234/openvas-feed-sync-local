# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108854");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2006-4625", "CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907",
                "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0988",
                "CVE-2007-1286", "CVE-2007-1376", "CVE-2007-1378", "CVE-2007-1379",
                "CVE-2007-1380", "CVE-2007-1700", "CVE-2007-1701", "CVE-2007-1777",
                "CVE-2007-1825", "CVE-2007-1835", "CVE-2007-1884", "CVE-2007-1885",
                "CVE-2007-1886", "CVE-2007-1887", "CVE-2007-1890");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 4.4.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_consolidation.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP prior to version 4.4.5.");

  script_tag(name:"solution", value:"Update to version 4.4.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22496");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23169");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23219");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/23236");

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

if (version_is_less(version: version, test_version: "4.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

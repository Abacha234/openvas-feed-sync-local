# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:concretecms:concrete_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112039");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-09-11 08:49:26 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-13 17:47:00 +0000 (Wed, 13 Sep 2017)");
  script_cve_id("CVE-2015-4721", "CVE-2015-4724");
  script_name("Concrete5 <= 5.7.3.1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_portlandlabs_concrete_cms_http_detect.nasl");
  script_mandatory_keys("concrete_cms/detected");

  script_tag(name:"summary", value:"Concrete5 is prone to multiple cross-site scripting (XSS) and
  SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Concrete5 versions up to and including 5.7.3.1.");

  script_tag(name:"solution", value:"Update to version 5.7.4.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/59664");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96891");
  script_xref(name:"URL", value:"https://hackerone.com/reports/59661");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"5.7.3.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

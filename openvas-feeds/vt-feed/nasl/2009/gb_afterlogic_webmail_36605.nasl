# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:afterlogic:webmail_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100314");
  script_version("2025-11-27T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-11-27 05:40:40 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-4743");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AfterLogic WebMail Pro <= 4.7.10 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_afterlogic_aurora_webmail_http_detect.nasl");
  script_mandatory_keys("afterlogic/aurora_webmail/detected");

  script_tag(name:"summary", value:"AfterLogic WebMail Pro is prone to multiple cross-site
  scripting (XSS) vulnerabilities because the application fails to sufficiently sanitize
  user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attacker-supplied HTML or JavaScript code could run in the
  context of the affected site, potentially allowing the attacker to steal cookie-based
  authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"AfterLogic WebMail Pro version 4.7.10 and prior.");

  script_tag(name:"solution", value:"Reports indicate that the vendor addressed these issues in
  WebMail Pro 4.7.11, but Symantec has not confirmed this. Please contact the vendor for more
  information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36605");

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

if (version_is_less_equal(version: version, test_version: "4.7.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

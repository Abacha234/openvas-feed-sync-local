# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133103");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-04 12:34:28 +0000 (Tue, 04 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-12642");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lighttpd 1.4.80 HTTP Request/Response Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_mandatory_keys("lighttpd/detected");

  script_tag(name:"summary", value:"Lighttpd is prone to an HTTP request/response smuggling
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The server incorrectly merged trailer fields into headers after
  http request parsing. This behavior can be exploited to conduct HTTP header smuggling attacks.
  Successful exploitation may allow an attacker to: bypass access control rules, inject unsafe
  input into backend logic that trusts request headers, and execute HTTP request smuggling attacks
  under some conditions.");

  script_tag(name:"affected", value:"Lighttpd version 1.4.80.");

  script_tag(name:"solution", value:"Update to version 1.4.81 or later.");

  script_xref(name:"URL", value:"https://github.com/lighttpd/lighttpd1.4/commit/35cb89c103877de62d6b63d0804255475d77e5e1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "1.4.80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.81");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125501");
  script_version("2025-11-18T05:39:54+0000");
  script_tag(name:"last_modification", value:"2025-11-18 05:39:54 +0000 (Tue, 18 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-14 16:22:14 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2025-61261");

  # nb: Since vulnerability occurs in specific CKEditor with Angular integration
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CKEditor <= 46.1.0 Reflected XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_http_detect.nasl");
  script_mandatory_keys("ckeditor/detected");

  script_tag(name:"summary", value:"CKEditor 5 is prone to a reflected cross-site scripting (XSS)
  vulnerability when used with Angular.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A reflected XSS vulnerability exists in CKEditor and allows
  attackers to execute arbitrary code in the context of a user's browser by injecting a crafted
  payload through the link feature using data URLs that bypass Angular's sanitization.");

  script_tag(name:"affected", value:"CKEditor version 46.1.0 and probably prior when integrated
  with Angular v18.0.0.");

  script_tag(name:"solution", value:"No known solution is available as of 14th November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://senscybersecurity.nl/cve-2025-61261-explained/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "46.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

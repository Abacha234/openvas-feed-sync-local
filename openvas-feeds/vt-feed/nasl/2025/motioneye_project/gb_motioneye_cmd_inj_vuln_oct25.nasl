# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:motioneye_project:motioneye";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155714");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-06 09:37:33 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2025-60787");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("motionEye <= 0.43.1b4 OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_motioneye_http_detect.nasl");
  script_mandatory_keys("motioneye/detected");

  script_tag(name:"summary", value:"motionEye is prone to an authenticated OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unsanitized user input is written to Motion configuration
  files, allowing remote authenticated attackers with admin access to achieve code execution when
  Motion is restarted.");

  script_tag(name:"affected", value:"motionEye version 0.43.1b4 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 06th November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/prabhatverma47/motionEye-RCE-through-config-parameter");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

# nb: Currently checking for 0.43.0 as 0.43.1 seems to be in beta and might fix it in the final release
if (version_is_less_equal(version: version, test_version: "0.43.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elog_project:elog";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155702");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-05 04:17:00 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-62618", "CVE-2025-64348", "CVE-2025-64349");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("ELOG <= 3.1.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elog_http_detect.nasl");
  script_mandatory_keys("elog/detected");

  script_tag(name:"summary", value:"ELOG is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-62618: Authenticated arbitrary HTML file upload

  - CVE-2025-64348: Denial of service (DoS) via authenticated configuration file overwrite

  - CVE-2025-64349: Authenticated user profile modification");

  script_tag(name:"affected", value:"ELOG version 3.1.5 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 05th November, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/7092ff64f6eb9521f8cc8c52272a020bf3730946");
  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/f81e5695c40997322fe2713bfdeba459d9de09dc");
  script_xref(name:"URL", value:"https://bitbucket.org/ritt/elog/commits/f81e5695c40997322fe2713bfdeba459d9de09dc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

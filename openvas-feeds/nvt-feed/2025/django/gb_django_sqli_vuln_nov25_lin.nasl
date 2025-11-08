# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155711");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-06 04:03:02 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2025-64459");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.26, 5.0.x < 5.1.14, 5.2.x < 5.2.8 SQLi Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an SQL injection (SQLi) vulnerability via
  _connector keyword argument in QuerySet and Q objects.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The methods QuerySet.filter(), QuerySet.exclude(), and
  QuerySet.get(), and the class Q() were subject to SQL injection when using a suitably crafted
  dictionary, with dictionary expansion, as the _connector argument.");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.26, 5.0.x, 5.1.x prior to
  5.1.14 and 5.2.x prior to 5.2.8.");

  script_tag(name:"solution", value:"Update to version 4.2.26, 5.1.14, 5.2.8 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/nov/05/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.26", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.14", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.8", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

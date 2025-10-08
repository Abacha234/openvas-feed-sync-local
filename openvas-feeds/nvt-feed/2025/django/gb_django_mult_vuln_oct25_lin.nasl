# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127967");
  script_version("2025-10-07T05:38:31+0000");
  script_tag(name:"last_modification", value:"2025-10-07 05:38:31 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-02 12:00:05 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2025-59681", "CVE-2025-59682");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.25, 5.0.x < 5.1.13, 5.2.x < 5.2.7 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-59681: QuerySet.annotate(), QuerySet.alias(), QuerySet.aggregate(), and
  QuerySet.extra() methods were subject to SQL injection in column aliases, using a suitably
  crafted dictionary, with dictionary expansion, as the **kwargs passed to these methods on MySQL
  and MariaDB.

  - CVE-2025-59682: The django.utils.archive.extract() function, used by startapp --template and
  startproject --template, allowed partial directory-traversal via an archive with file paths
  sharing a common prefix with the target directory.");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.25, 5.0.x prior to 5.1.13 and
  5.2.x prior to 5.2.7.");

  script_tag(name:"solution", value:"Update to version 4.2.25, 5.1.13, 5.2.7 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/oct/01/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.25", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.13", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

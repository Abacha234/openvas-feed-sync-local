# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125404");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-28 08:24:34 +0000 (Tue, 28 Oct 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2025-61795");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Oct 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an error occurs (including exceeding limits) during the
  processing of a multipart upload, temporary copies of the uploaded parts written to disk are not
  cleaned up immediately and are left for the garbage collection process to delete. Depending on JVM
  settings, application memory usage, and application load, the space for these temporary copies can
  fill faster than the garbage collector clears them, potentially leading to a DoS.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 through 9.0.109, 10.1.0-M1
  through 10.1.46 and 11.0.0-M1 through 11.0.11.

  Vendor note: Older, EOL versions may also be affected.");

  script_tag(name:"solution", value:"Update to version 9.0.110, 10.1.47, 11.0.12 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/wm9mx8brmx9g4zpywm06ryrtvd3160pp");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.12");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.47");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.110");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/27/6");

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

if (version_in_range(version: version, test_version: "9.0.0.M1", test_version2: "9.0.109")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.110", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0.M1", test_version2: "10.1.46")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0.0.M1", test_version2: "11.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

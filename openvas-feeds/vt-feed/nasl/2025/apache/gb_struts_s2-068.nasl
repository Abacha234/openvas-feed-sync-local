# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155909");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-02 02:44:19 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-64775");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts DoS Vulnerability (S2-068)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"File leak in multipart request processing causes disk
  exhaustion.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 2.3.37, 2.5.0 through
  2.5.33. 6.0.0 through 6.7.0 and 7.0.0 through 7.0.3.");

  script_tag(name:"solution", value:"Update to version 6.8.0, 7.1.1 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-068");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/01/2");
  script_xref(name:"Advisory-ID", value:"S2-068");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "6.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

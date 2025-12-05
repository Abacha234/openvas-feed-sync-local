# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118771");
  script_version("2025-12-04T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-12-04 05:40:45 +0000 (Thu, 04 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-03 12:13:37 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2025-13372", "CVE-2025-64460");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.2.x < 4.2.27, 5.0.x < 5.1.15, 5.2.x < 5.2.9 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-13372: Potential SQL injection in FilteredRelation column aliases on PostgreSQL

  'FilteredRelation' is subject to SQL injection in column aliases, using a suitably crafted
  dictionary, with dictionary expansion, as the '**kwargs' passed to 'QuerySet.annotate()' or
  'QuerySet.alias()' on PostgreSQL.

  - CVE-2025-64460: Potential denial-of-service (DoS) in XML serializer text extraction

  Algorithmic complexity in django.core.serializers.xml_serializer.getInnerText() allows a remote
  attacker to cause a potential DoS triggering CPU and memory exhaustion via specially crafted XML
  input submitted to a service that invokes XML Deserializer. The vulnerability results from
  repeated string concatenation while recursively collecting text nodes, which produces superlinear
  computation resulting in service degradation or outage.");

  script_tag(name:"affected", value:"Django version 4.2.x prior to 4.2.27, 5.1.x prior to 5.1.15 and
  5.2.x prior to 5.2.9.

  Note: The vendor is only evaluating the affected status of supported versions but EOL versions
  like 5.0.x in between the affected versions are also assumed to be affected.");

  script_tag(name:"solution", value:"Update to version 4.2.27, 5.1.15, 5.2.9 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/dec/02/security-releases/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/02/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.2", test_version_up: "4.2.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.27", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.15", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.9", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

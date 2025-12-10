# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124597");
  script_version("2025-12-09T05:47:47+0000");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-04 07:21:17 +0000 (Thu, 04 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2025-30189");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.4.0 < 2.4.2 Improper Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to an improper access control
  vulnerability.");

  script_tag(name:"insight", value:"When cache is enabled, some `passdb/userdb` drivers incorrectly
  cache all users with same cache key, causing wrong cached information to be used for these users.
  After cached login, all subsequent logins are for same user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot version 2.4.0 prior to 2.4.2.");

  script_tag(name:"solution", value:"Update to version 2.4.2 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/29/4");
  script_xref(name:"URL", value:"https://documentation.open-xchange.com/dovecot/security/advisories/csaf/2025/oxdc-adv-2025-0001.json");

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

if (version_in_range(version: version, test_version: "2.4.0", test_version2: "2.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

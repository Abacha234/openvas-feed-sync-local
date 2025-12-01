# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155747");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-11 09:00:58 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-62875");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD 7.7.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Trivial local denial of service (DoS) attack vector in the
  local API which allows unprivileged users to cause the shutdown of all smtpd services.");

  script_tag(name:"affected", value:"OpenSMTPD version 7.7.0 only.");

  script_tag(name:"solution", value:"Update to version 7.8.0 or later.");

  script_xref(name:"URL", value:"https://security.opensuse.org/2025/10/31/opensmtpd-local-DoS.html");

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

if (version_is_equal(version: version, test_version: "7.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

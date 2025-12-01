# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836873");
  script_version("2025-11-28T05:40:45+0000");
  script_cve_id("CVE-2025-13674");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-24 15:52:17 +0530 (Mon, 24 Nov 2025)");
  script_name("Wireshark Security Update (wnpa-sec-2025-05) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to crash the system by injecting a malformed packet onto the network or by
  convincing a user to open a malicious packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 4.6.0 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2025-05.html");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version: vers, test_version: "4.6.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.6.1", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
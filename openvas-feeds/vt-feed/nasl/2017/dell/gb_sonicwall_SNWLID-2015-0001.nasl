# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:sonicwall:s";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106576");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-02-08 12:16:13 +0700 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2248");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL SMA 100 / SRA Series CSRF Vulnerability (SNWLID-2015-0001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_sra_consolidation.nasl");
  script_mandatory_keys("sonicwall/sra_sma/detected");

  script_tag(name:"summary", value:"Dell SonicWALL SMA 100 Series and SRA Series appliances are
  prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability affects an unknown function of the file
  /cgi-bin/editBookmark. The manipulation with an unknown input leads to a cross site request
  forgery vulnerability.");

  script_tag(name:"impact", value:"The vulnerability enables someone to convince a user to create a
  malicious bookmark that can then be used to steal account information associated with the
  bookmark.");

  script_tag(name:"affected", value:"Dell SonicWALL SMA 100 and SRA Series appliances versions
  7.5.0.x and 8.0.0.x.");

  script_tag(name:"solution", value:"Update to version 7.5.1.0-38sv, 8.0.0.1-16sv or later.");

  script_xref(name:"URL", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2015-0001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

# nb: SRA devices currently have / get CPEs like e.g.:
# - cpe:/o:sonicwall:sra_virtual_appliance_firmware
if (cpe !~ "^cpe:/o:sonicwall:(sma_(200|210|400|410|500)|sra)")
  exit(0);

port = infos["port"];

if (!version = get_app_version(port: port, cpe: cpe, nofork: TRUE))
  exit(0);

check_vers = ereg_replace(string: version, pattern: "-", replace: ".");

if (version_is_less(version: check_vers, test_version: "7.5.1.0.38sv")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.1.0-38sv");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^8\.0\.0") {
  if (version_is_less(version: check_vers, test_version: "8.0.0.1.16sv")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1-16sv");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

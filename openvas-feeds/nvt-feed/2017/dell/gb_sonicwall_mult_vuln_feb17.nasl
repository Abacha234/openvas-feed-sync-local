# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:sonicwall:s";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106980");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-07-24 13:41:24 +0700 (Mon, 24 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-17 10:29:00 +0000 (Wed, 17 Oct 2018)");

  script_cve_id("CVE-2016-9682", "CVE-2016-9683", "CVE-2016-9684");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell SonicWALL SMA 100 / SRA Series Multiple RCE Vulnerabilities (SNWLID-2016-0003, SNWLID-2016-0004, SNWLID-2016-0005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_sra_consolidation.nasl");
  script_mandatory_keys("sonicwall/sra_sma/detected");

  script_tag(name:"summary", value:"Dell SonicWALL SMA 100 Series and SRA Series appliances are
  prone to multiple remote command execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - No CVE: The vulnerability exists in a section of the machine's administrative interface for
  performing configurations related to on-connect scripts to be launched for users's connecting.

  - CVE-2016-9682: Two Remote Command Injection vulnerabilities in its web administrative interface.
  These vulnerabilities occur in the diagnostics CGI (/cgi-bin/diagnostics) component responsible
  for emailing out information about the state of the system.

  - CVE-2016-9683: Remote Command Injection vulnerability in its web administrative interface. This
  vulnerability occurs in the 'extensionsettings' CGI (/cgi-bin/extensionsettings) component
  responsible for handling some of the server's internal configurations.

  - CVE-2016-9684: Remote Command Injection vulnerability in its web administrative interface. This
  vulnerability occurs in the 'viewcert' CGI (/cgi-bin/viewcert) component responsible for
  processing SSL certificate information.");

  script_tag(name:"impact", value:"An attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Dell SonicWALL SMA 100 and SRA Series appliances versions
  7.5.0.x, 8.0.0.x, 8.1.0.x and 8.5.0.x.");

  # nb:
  # - Advisories are a little bit confusingly written as it seems to mentioned the fixed versions
  #   add different part. A best guess on all fixed versions has been done here for now.
  # - The issue has been also reported to the vendor PSIRT in 10/2025.
  script_tag(name:"solution", value:"Update to version 7.5.1.0.38sv, 8.0.0.1.16sv, 8.1.0.7-22sv,
  8.5.0.4-18sv or later.");

  script_xref(name:"URL", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2016-0003");
  script_xref(name:"URL", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2016-0004");
  script_xref(name:"URL", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2016-0005");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42343/");

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

if (version =~ "^8\.1\.0") {
  if (version_is_less(version: check_vers, test_version: "8.1.0.7-22sv")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.1.0.7-22sv");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^8\.[2-5]\.0") {
  if (version_is_less(version: check_vers, test_version: "8.5.0.4-18sv")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.4-18sv");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

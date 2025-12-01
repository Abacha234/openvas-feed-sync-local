# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125490");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 14:30:00 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 18:37:12 +0000 (Wed, 26 Feb 2020)");

  script_cve_id("CVE-2020-8793", "CVE-2020-8794");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD < 6.6.4 Multiple Vulnerabilities (Feb 2020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-8793: Untrusted search path in makemap.c combined with race
  conditions in offline functionality allows local users to read arbitrary
  files.

  - CVE-2020-8794: Out-of-bounds read in mta_io in mta_session.c for multi-line
  replies allows remote code execution. The vulnerability affects the client side
  but can attack a server because server code launches client code during bounce
  handling.");

  script_tag(name:"affected", value:"OpenSMTPD prior to version 6.6.4.");

  script_tag(name:"solution", value:"Update to version 6.6.4 or later.");

  script_xref(name:"URL", value:"https://www.openbsd.org/security.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4634");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2020/03/01/2");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2020/Feb/32");

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

if (version_is_less(version: version, test_version: "6.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

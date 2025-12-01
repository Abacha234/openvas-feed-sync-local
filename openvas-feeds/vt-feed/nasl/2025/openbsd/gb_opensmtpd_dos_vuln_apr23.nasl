# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125493");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 14:30:00 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-12 14:56:20 +0000 (Wed, 12 Apr 2023)");

  script_cve_id("CVE-2023-29323");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD < 7.3.0p0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The ascii_load_sockaddr function in smtpd can abort upon a
  connection from a local, scoped IPv6 address. This vulnerability affects both OpenBSD and
  OpenSMTPD Portable versions.");

  script_tag(name:"affected", value:"OpenSMTPD prior to version 7.3.0p0.");

  script_tag(name:"solution", value:"Update to OpenSMTPD 7.3.0p0 or later.");

  script_xref(name:"URL", value:"https://github.com/openbsd/src/commit/f748277ed1fc7065ae8998d61ed78b9ab1e55fae");
  script_xref(name:"URL", value:"https://github.com/OpenSMTPD/OpenSMTPD/commit/41d0eae481f538956b1f1fbadfb535043454061f");
  script_xref(name:"URL", value:"https://undeadly.org/cgi?action=article;sid=20230617111340");

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

if (version_is_less(version: version, test_version: "7.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0p0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

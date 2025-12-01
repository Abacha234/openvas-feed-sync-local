# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125491");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 14:30:00 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-01 11:50:35 +0000 (Wed, 01 Nov 2017)");

  script_cve_id("CVE-2015-7687");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD < 5.7.2 Use-after-free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to a use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A use-after-free vulnerability in OpenSMTPD allows remote
  attackers to cause a denial of service (crash) or execute arbitrary code via vectors involving
  req_ca_vrfy_smtp and req_ca_vrfy_mta.");

  script_tag(name:"affected", value:"OpenSMTPD prior to version 5.7.2.");

  script_tag(name:"solution", value:"Update to version 5.7.2 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1268793");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/03/1");

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

if (version_is_less(version: version, test_version: "5.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:concretecms:concrete_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147192");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2021-11-22 05:15:51 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 13:36:00 +0000 (Tue, 23 Nov 2021)");

  script_cve_id("CVE-2021-22970");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Concrete CMS 9.0.0 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_portlandlabs_concrete_cms_http_detect.nasl");
  script_mandatory_keys("concrete_cms/detected");

  script_tag(name:"summary", value:"Concrete CMS is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Concrete allowed local IP importing causing the system to be
  vulnerable to SSRF attacks on the private LAN servers and SSRF mitigation bypass through DNS
  rebinding.");

  script_tag(name:"affected", value:"Concrete CMS version 9.0.0.");

  script_tag(name:"solution", value:"Update to version 9.0.1 or later.");

  script_xref(name:"URL", value:"https://documentation.concretecms.org/developers/introduction/version-history/901-release-notes");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "9.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

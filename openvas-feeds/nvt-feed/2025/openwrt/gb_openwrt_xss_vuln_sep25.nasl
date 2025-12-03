# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155904");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-01 07:25:22 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-57389");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 19.07.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to a reflected cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A reflected cross-site scripting (XSS) vulnerability in the
  /admin/system/packages endpoint allows attackers to execute arbitrary Javascript in the context
  of a user's browser via a crafted payload.");

  script_tag(name:"affected", value:"OpenWRT prior to version 19.07.0.");

  script_tag(name:"solution", value:"Update to version 19.07.0 or later.");

  script_xref(name:"URL", value:"https://github.com/amalcew/CVE-2025-57389");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "19.07.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.07.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

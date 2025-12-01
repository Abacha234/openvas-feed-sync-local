# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155738");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-11 03:52:09 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-62847", "CVE-2025-62848", "CVE-2025-62849");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-25-45)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QTS version 5.x prior to 5.2.7.3297 build 20251024.

  Note: Due to the EOL status of 5.0.x and 5.1.x branches it is assumed that all 5.x versions are
  affected and not only the 5.2.x one as mentioned by the vendor.");

  script_tag(name:"solution", value:"Update to version 5.2.7.3297 build 20251024 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-45");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^5\.") {
  if (version_is_less(version: version, test_version: "5.2.7.3297")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.7.3297", fixed_build: "20251024");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "5.2.7.3297") &&
      (!build || version_is_less(version: build, test_version: "20251024"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "5.2.7.3297", fixed_build: "20251024");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

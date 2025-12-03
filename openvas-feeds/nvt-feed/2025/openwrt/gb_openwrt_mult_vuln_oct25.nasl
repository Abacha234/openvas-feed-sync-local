# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155903");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-01 07:12:01 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-30 17:34:02 +0000 (Thu, 30 Oct 2025)");

  script_cve_id("CVE-2025-62525", "CVE-2025-62526");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 24.10.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-62525: Local users could read and write arbitrary kernel memory using the ioctls of
  the ltq-ptm driver which is used to drive the datapath of the DSL line.

  - CVE-2025-62526: ubusd contains a heap buffer overflow in the event registration parsing
  code.");

  script_tag(name:"affected", value:"OpenWRT prior to version 24.10.4.");

  script_tag(name:"solution", value:"Update to version 24.10.4 or later.");

  script_xref(name:"URL", value:"https://openwrt.org/advisory/2025-10-22-1");
  script_xref(name:"URL", value:"https://openwrt.org/advisory/2025-10-22-2");
  script_xref(name:"URL", value:"https://github.com/openwrt/openwrt/security/advisories/GHSA-h427-frpr-7cqr");
  script_xref(name:"URL", value:"https://github.com/openwrt/openwrt/security/advisories/GHSA-cp32-65v4-cp73");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "24.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.10.4");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

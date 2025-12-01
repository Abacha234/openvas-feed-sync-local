# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125538");
  script_version("2025-11-25T05:40:35+0000");
  script_tag(name:"last_modification", value:"2025-11-25 05:40:35 +0000 (Tue, 25 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-24 13:23:39 +0000 (Mon, 24 Nov 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-13392");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) Authentication Bypass Vulnerability (Synology-SA-25:14) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"DSM allows remote attackers to bypass authentication
  with prior knowledge of the distinguished name (DN).");

  script_tag(name:"affected", value:"Synology DSM version 7.2.2 prior to 7.2.2-72806-5 and
  7.3 prior to 7.3.1-86003-1.");

  script_tag(name:"solution", value:"Update to version 7.2.2-72806-5, 7.3.1-86003-1 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_25_14");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.3.1-86003-1 and not 7.3.1-86003), there will be 2 VTs with different qod_type.
if (version =~ "^7\.2\.2" && (revcomp(a: version, b: "7.2.2-72806") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2-72806-5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.3" && (revcomp(a: version, b: "7.3.1-86003") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.1-86003-1");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.125539
if (version =~ "^7\.2\.2-72806" || version =~ "^7\.3\.1-86003")
  exit(0);

exit(99);

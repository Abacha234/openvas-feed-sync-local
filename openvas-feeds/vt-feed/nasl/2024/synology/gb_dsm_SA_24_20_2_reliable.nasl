# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125546");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  # nb: This was initially a single set of two VTs which got split later due to different affected
  # and fixed versions. As all CVEs have been covered back then the original creation date was kept.
  script_tag(name:"creation_date", value:"2024-11-12 14:14:35 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-17 13:42:21 +0000 (Mon, 17 Nov 2025)");

  script_cve_id("CVE-2024-10445");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) File Write Vulnerability (Synology-SA-24:20) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a file write
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper certificate validation vulnerability in the update
  functionality allows remote attackers to write limited files via unspecified vectors.");

  script_tag(name:"affected", value:"Synology DSM version 6.2.4 prior to 6.2.4-25556-8, 7.1.1
  prior to 7.1.1-42962-7, 7.2 prior to 7.2-64570-4, 7.2.1 prior to 7.2.1-69057-6 and 7.2.2
  prior to 7.2.2-72806-1.");

  script_tag(name:"solution", value:"Update to version 6.2.4-25556-8, 7.1.1-42962-7, 7.2-64570-4,
  7.2.1-69057-6, 7.2.2-72806-1 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_20");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 6.2.4-25556-8 and not 6.2.4-25556), there will be 2 VTs with different qod_type.
if (version =~ "^6\.2\.4" && (revcomp(a: version, b: "6.2.4-25556") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.4-25556-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.1\.1" && (revcomp(a: version, b: "7.1.1-42962") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1-42962-7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2" && version !~ "^7\.2\.[12]" && (revcomp(a: version, b: "7.2-64570") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2-64570-4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.1" && (revcomp(a: version, b: "7.2.1-69057") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1-69057-6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.2" && (revcomp(a: version, b: "7.2.2-72806") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2-72806-1");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.125547
if (version =~ "^6\.2\.4-25556" || version =~ "^7\.1\.1-42962" || version =~ "^7\.2-64570" ||
    version =~ "^7\.2\.1-69057" || version =~ "^7\.2\.2-72806")
  exit(0);

exit(99);

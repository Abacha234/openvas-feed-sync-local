# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.138016");
  script_version("2026-01-09T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-09 05:47:51 +0000 (Fri, 09 Jan 2026)");
  script_tag(name:"creation_date", value:"2025-12-09 08:17:59 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-05 21:43:56 +0000 (Fri, 05 Dec 2025)");

  script_cve_id("CVE-2024-5401");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) Privilege Escalation (Synology-SA-24:27) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An improper control of dynamically-managed code resources in
  WebAPI component in Synology DiskStation Manager (DSM) allows remote authenticated users to
  obtain privileges without consent via unspecified vectors.");

  script_tag(name:"impact", value:"The flaws allows remote authenticated users to obtain privileges
  without consent.");

  script_tag(name:"affected", value:"Synology DSM prior to version 7.1.1-42962-8, 7.2.1 prior to
  7.2.1-69057-2 and 7.2.2 prior to 7.2.2-72806.");

  script_tag(name:"solution", value:"Update to version 7.1.1-42962-8, 7.2.1-69057-2, 7.2.2-72806
  or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_27");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: The patch level version cannot be obtained so when the fix is on a patch level version (e.g.
# 7.2.1-69057-2 and not 7.2.1-69057), there will be 2 VTs with different qod_type.
if (revcomp(a: version, b: "7.1.1-42962") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1-42962-8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.1" && (revcomp(a: version, b: "7.2.1-69057") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1-69057-2");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.2\.2" && (revcomp(a: version, b: "7.2.2-72806") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.2-72806");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.138017
if (version =~ "^7\.2\.1-69057" || version =~ "7\.1\.1-42962")
  exit(0);

exit(99);

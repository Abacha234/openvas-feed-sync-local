# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.98");
  script_cve_id("CVE-2025-14860", "CVE-2025-14861");
  script_tag(name:"creation_date", value:"2025-12-18 16:05:55 +0000 (Thu, 18 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_origin", value:"Vendor");
  script_tag(name:"severity_date", value:"2025-12-17 23:00:00 +0000 (Wed, 17 Dec 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-98) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-98");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-98/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1996570%2C1999700");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2000597");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2025-98.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-14860: Use-after-free in the Disability Access APIs component

CVE-2025-14861: Memory safety bugs fixed in Firefox 146.0.1

Memory safety bugs present in Firefox 146. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 146.0.1.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "146.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "146.0.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
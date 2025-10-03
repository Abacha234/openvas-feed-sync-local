# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.80");
  script_cve_id("CVE-2025-11152", "CVE-2025-11153");
  script_tag(name:"creation_date", value:"2025-10-01 11:26:21 +0000 (Wed, 01 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-80) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-80");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-80/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1987246");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1987481");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2025-80.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-11152: Sandbox escape due to integer overflow in the Graphics: Canvas2D component

CVE-2025-11153: JIT miscompilation in the JavaScript Engine: JIT component");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 143.0.3.");

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

if (version_is_less(version: version, test_version: "143.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "143.0.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

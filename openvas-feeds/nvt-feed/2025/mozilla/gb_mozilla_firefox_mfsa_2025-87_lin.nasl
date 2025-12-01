# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.87");
  script_cve_id("CVE-2025-13012", "CVE-2025-13013", "CVE-2025-13014", "CVE-2025-13015", "CVE-2025-13016", "CVE-2025-13017", "CVE-2025-13018", "CVE-2025-13019", "CVE-2025-13020", "CVE-2025-13021", "CVE-2025-13022", "CVE-2025-13023", "CVE-2025-13024", "CVE-2025-13025", "CVE-2025-13026", "CVE-2025-13027");
  script_tag(name:"creation_date", value:"2025-11-12 09:28:42 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_origin", value:"Vendor");
  script_tag(name:"severity_date", value:"2025-11-10 23:00:00 +0000 (Mon, 10 Nov 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-87) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-87");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-87/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1980904");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1984940");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1986431");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1987237%2C1990079%2C1991715%2C1994994");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1988412");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1988488");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1991458");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1991945");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1992032");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1992130");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1992902");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1994022");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1994164");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1994241");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1994441");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1995686");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2025-87.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-13021: Incorrect boundary conditions in the Graphics: WebGPU component

CVE-2025-13022: Incorrect boundary conditions in the Graphics: WebGPU component

CVE-2025-13012: Race condition in the Graphics component

CVE-2025-13023: Sandbox escape due to incorrect boundary conditions in the Graphics: WebGPU component

CVE-2025-13016: Incorrect boundary conditions in the JavaScript: WebAssembly component

CVE-2025-13024: JIT miscompilation in the JavaScript Engine: JIT component

CVE-2025-13025: Incorrect boundary conditions in the Graphics: WebGPU component

CVE-2025-13026: Sandbox escape due to incorrect boundary conditions in the Graphics: WebGPU component

CVE-2025-13017: Same-origin policy bypass in the DOM: Notifications component

CVE-2025-13018: Mitigation bypass in the DOM: Security component

CVE-2025-13019: Same-origin policy bypass in the DOM: Workers component

CVE-2025-13013: Mitigation bypass in the DOM: Core & HTML component

CVE-2025-13020: Use-after-free in the WebRTC: Audio/Video component

CVE-2025-13014: Use-after-free in the Audio/Video component

CVE-2025-13015: Spoofing issue in Firefox

CVE-2025-13027: Memory safety bugs fixed in Firefox 145 and Thunderbird 145

Memory safety bugs present in Firefox 144 and Thunderbird 144. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 145.");

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

if (version_is_less(version: version, test_version: "145")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "145", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

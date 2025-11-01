# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.01");
  script_cve_id("CVE-2023-23597", "CVE-2023-23598", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23604", "CVE-2023-23605", "CVE-2023-23606");
  script_tag(name:"creation_date", value:"2023-01-18 09:32:25 +0000 (Wed, 18 Jan 2023)");
  script_version("2025-09-26T15:41:32+0000");
  script_tag(name:"last_modification", value:"2025-09-26 15:41:32 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 13:51:09 +0000 (Thu, 08 Jun 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1538028");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1764921%2C1802690%2C1806974");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1764974%2C1798591%2C1799201%2C1800446%2C1801248%2C1802100%2C1803393%2C1804626%2C1804971%2C1807004");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1794268");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1800425");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1800832");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1800890");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1802346");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2023-01.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-23597: Logic bug in process allocation allowed to read arbitrary files

A compromised web child process could disable web security opening restrictions, leading to a new child process being spawned within the file:// context. Given a reliable exploit primitive, this new process could be exploited again leading to arbitrary file read.

CVE-2023-23598: Arbitrary file read from GTK drag and drop on Linux

Due to the Firefox GTK wrapper code's use of text/plain for drag data and GTK treating all text/plain MIMEs containing file URLs as being dragged a website could arbitrarily read a file via a call to DataTransfer.setData.

CVE-2023-23601: URL being dragged from cross-origin iframe into same tab triggers navigation

Navigations were being allowed when dragging a URL from a cross-origin iframe into the same tab which could lead to website spoofing attacks

CVE-2023-23602: Content Security Policy wasn't being correctly applied to WebSockets in WebWorkers

A mishandled security check when creating a WebSocket in a WebWorker caused the Content Security Policy connect-src header to be ignored. This could lead to connections to restricted origins from inside WebWorkers.

CVE-2023-23603: Calls to console.log allowed bypassing Content Security Policy via format directive

Regular expressions used to filter out forbidden properties and values from style directives in calls to console.log weren't accounting for external URLs. Data could then be potentially exfiltrated from the browser.

CVE-2023-23604: Creation of duplicate SystemPrincipal from less secure contexts

A duplicate SystemPrincipal object could be created when parsing a non-system html document via DOMParser::ParseFromSafeString. This could have lead to bypassing web security checks.

CVE-2023-23605: Memory safety bugs fixed in Firefox 109 and Firefox ESR 102.7

Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108 and Firefox ESR 102.6. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2023-23606: Memory safety bugs fixed in Firefox 109

Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 109.");

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

if (version_is_less(version: version, test_version: "109")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "109", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

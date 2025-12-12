# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.92");
  script_cve_id("CVE-2025-14321", "CVE-2025-14322", "CVE-2025-14323", "CVE-2025-14324", "CVE-2025-14325", "CVE-2025-14326", "CVE-2025-14327", "CVE-2025-14328", "CVE-2025-14329", "CVE-2025-14330", "CVE-2025-14331", "CVE-2025-14332", "CVE-2025-14333");
  script_tag(name:"creation_date", value:"2025-12-10 10:22:05 +0000 (Wed, 10 Dec 2025)");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:22:53 +0000 (Wed, 10 Dec 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-92) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-92");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-92/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1840666");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1963153%2C1985058%2C1995637%2C1997118");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1966501%2C1997639");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1970743");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1992760");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1996473");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1996555");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1996761");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1996840");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1997018");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1997503");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1998050");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=2000218");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2025-92.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-14321: Use-after-free in the WebRTC: Signaling component

CVE-2025-14322: Sandbox escape due to incorrect boundary conditions in the Graphics: CanvasWebGL component

CVE-2025-14323: Privilege escalation in the DOM: Notifications component

CVE-2025-14324: JIT miscompilation in the JavaScript Engine: JIT component

CVE-2025-14325: JIT miscompilation in the JavaScript Engine: JIT component

CVE-2025-14326: Use-after-free in the Audio/Video: GMP component

CVE-2025-14327: Spoofing issue in the Downloads Panel component

CVE-2025-14328: Privilege escalation in the Netmonitor component

CVE-2025-14329: Privilege escalation in the Netmonitor component

CVE-2025-14330: JIT miscompilation in the JavaScript Engine: JIT component

CVE-2025-14331: Same-origin policy bypass in the Request Handling component

CVE-2025-14332: Memory safety bugs fixed in Firefox 146 and Thunderbird 146

Memory safety bugs present in Firefox 145 and Thunderbird 145. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-14333: Memory safety bugs fixed in Firefox ESR 140.6, Thunderbird ESR 140.6, Firefox 146 and Thunderbird 146

Memory safety bugs present in Firefox ESR 140.5, Thunderbird ESR 140.5, Firefox 145 and Thunderbird 145. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 146.");

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

if (version_is_less(version: version, test_version: "146")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "146", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
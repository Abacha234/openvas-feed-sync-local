# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2025.81");
  script_cve_id("CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11714", "CVE-2025-11715", "CVE-2025-11721");
  script_tag(name:"creation_date", value:"2025-10-15 06:12:41 +0000 (Wed, 15 Oct 2025)");
  script_version("2025-10-16T07:37:11+0000");
  script_tag(name:"last_modification", value:"2025-10-16 07:37:11 +0000 (Thu, 16 Oct 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-15 14:15:44 +0000 (Wed, 15 Oct 2025)");

  script_name("Mozilla Firefox Security Advisory (MFSA2025-81) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2025-81");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-81/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1973699%2C1989945%2C1990970%2C1991040%2C1992113");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1979536");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1983838%2C1987624%2C1988244%2C1988912%2C1989734%2C1990085%2C1991899");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1986816");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1988931");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1989127");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1989899");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1989978");

  script_tag(name:"summary", value:"The remote host is missing an update for Mozilla Firefox, announced via the advisory MFSA2025-81.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-11708: Use-after-free in MediaTrackGraphImpl::GetInstance()

Use-after-free in MediaTrackGraphImpl::GetInstance()

CVE-2025-11709: Out of bounds read/write in a privileged process triggered by WebGL textures

A compromised web process was able to trigger out of bounds reads and writes in a more privileged process using manipulated WebGL textures.

CVE-2025-11710: Cross-process information leaked due to malicious IPC messages

A compromised web process using malicious IPC messages could have caused the privileged browser process to reveal blocks of its memory to the compromised process.

CVE-2025-11711: Some non-writable Object properties could be modified

There was a way to change the value of JavaScript Object properties that were supposed to be non-writeable.

CVE-2025-11712: An OBJECT tag type attribute overrode browser behavior on web resources without a content-type

A malicious page could have used the type attribute of an OBJECT tag to override the default browser behavior when encountering a web resource served without a content-type. This could have contributed to an XSS on a site that unsafely serves files without a content-type header.

CVE-2025-11714: Memory safety bugs fixed in Firefox ESR 115.29, Firefox ESR 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144

Memory safety bugs present in Firefox ESR 115.28, Firefox ESR 140.3, Thunderbird ESR 140.3, Firefox 143 and Thunderbird 143. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-11715: Memory safety bugs fixed in Firefox ESR 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144

Memory safety bugs present in Firefox ESR 140.3, Thunderbird ESR 140.3, Firefox 143 and Thunderbird 143. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2025-11721: Memory safety bug fixed in Firefox 144 and Thunderbird 144

Memory safety bug present in Firefox 143 and Thunderbird 143. This bug showed evidence of memory corruption and we presume that with enough effort this could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox versions prior to 144.");

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

if (version_is_less(version: version, test_version: "144")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "144", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

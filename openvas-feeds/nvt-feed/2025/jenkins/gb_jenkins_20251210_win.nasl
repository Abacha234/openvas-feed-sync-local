# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128186");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-11 08:08:40 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-67635", "CVE-2025-67636", "CVE-2025-67637", "CVE-2025-67638",
  "CVE-2025-67639");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.319.2, < 2.330 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-67635: Jenkins does not properly close HTTP-based CLI connections when the connection
  stream becomes corrupted, allowing unauthenticated attackers to cause a denial of service.

  - CVE-2025-67636: A missing permission check in Jenkins allows attackers with View/Read
  permission to view encrypted password values in views.

  - CVE-2025-67637: Jenkins stores build authorization tokens unencrypted in job config.xml files
  on the Jenkins controller where they can be viewed by users with Item/Extended Read permission
  or access to the Jenkins controller file system.

  - CVE-2025-67638: Jenkins does not mask build authorization tokens displayed on the job
  configuration form, increasing the potential for attackers to observe and capture them.

  - CVE-2025-67639: A cross-site request forgery (CSRF) vulnerability in Jenkins allows attackers
  to trick users into logging in to the attacker's account.");

  script_tag(name:"affected", value:"Jenkins version through 2.540 and LTS version through
  2.528.2.");

  script_tag(name:"solution", value:"Update to version Jenkins 2.541, LTS 2.528.3 or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2025-12-10/#SECURITY-3630");
  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2025-12-10/#SECURITY-1809");
  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2025-12-10/#SECURITY-783");
  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2025-12-10/#SECURITY-1166");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (get_kb_item("jenkins/" + port + "/is_lts")) {
  if (version_is_less_equal(version: version, test_version: "2.528.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.528.3", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_is_less_equal(version: version, test_version: "2.540")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.541", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}
exit(99);

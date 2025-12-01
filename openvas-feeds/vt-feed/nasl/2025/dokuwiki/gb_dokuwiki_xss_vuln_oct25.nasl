# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dokuwiki:dokuwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124572");
  script_version("2025-11-20T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-11-20 05:40:06 +0000 (Thu, 20 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-10 07:27:42 +0200 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2025-61224");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DokuWiki <= 2025-05-14a XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"DokuWiki is prone to reflected cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated Reflected Cross-Site Scripting (XSS) in the
  search query parameter of the main page. An attacker can craft a malicious URL containing
  malicious JavaScript code in the query parameters, which, when visited by a user, executes the
  script within the context of the affected site.");

  script_tag(name:"affected", value:"DokuWiki version 2025-05-14a and prior.");

  script_tag(name:"solution", value:"Upgrade to pull request #441593 respectively to fix the
  issues.");

  script_xref(name:"URL", value:"https://github.com/dokuwiki/dokuwiki/issues/4512");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (revcomp(a: version, b: "2025-05-14a") <= 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

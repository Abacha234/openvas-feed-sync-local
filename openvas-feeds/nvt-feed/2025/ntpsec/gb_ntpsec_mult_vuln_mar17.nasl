# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntpsec:ntpsec";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119246");
  script_version("2025-12-09T05:47:47+0000");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-08 09:05:00 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-30 14:10:56 +0000 (Thu, 30 Mar 2017)");

  script_cve_id("CVE-2017-6464", "CVE-2017-6463", "CVE-2017-6458", "CVE-2017-6451",
                "CVE-2014-9295");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTPsec < 0.9.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("ntpsec/detected");

  script_tag(name:"summary", value:"NTPsec is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  # nb: Only the GitLab NEWS.adoc file includes the additional 2014 CVE.
  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-6464: Denial of service (DoS) via Malformed Config

  - CVE-2017-6463: Authenticated DoS via Malicious Config Option

  - CVE-2017-6458: Potential Overflows in ctl_put() functions

  - CVE-2017-6451: Improper use of snprintf() in mx4200_send()

  - CVE-2014-9295: Multiple stack-based buffer overflows which had been reintroduced into the
  code");

  script_tag(name:"affected", value:"NTPsec versions prior to 0.9.7.");

  script_tag(name:"solution", value:"Update to version 0.9.7 or later.");

  script_xref(name:"URL", value:"https://blog.ntpsec.org/2017/03/21/version-0-9-7.html");
  script_xref(name:"URL", value:"https://gitlab.com/NTPsec/ntpsec/-/blob/0539c4c9f53601166aa2c2a9f5d048e20b6636f4/NEWS.adoc#user-content-2017-03-21-0-9-7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "0.9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.7", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);

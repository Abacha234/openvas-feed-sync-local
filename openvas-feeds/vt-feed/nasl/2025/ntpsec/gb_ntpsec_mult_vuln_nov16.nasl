# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntpsec:ntpsec";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119247");
  script_version("2025-12-09T05:47:47+0000");
  script_tag(name:"last_modification", value:"2025-12-09 05:47:47 +0000 (Tue, 09 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-08 09:05:00 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 18:20:25 +0000 (Thu, 18 Jun 2020)");

  script_cve_id("CVE-2016-7434", "CVE-2016-7429", "CVE-2016-9311", "CVE-2016-9310");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTPsec < 0.9.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("ntpsec/detected");

  script_tag(name:"summary", value:"NTPsec is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-7434: Null pointer dereference on malformed mrulist request

  - CVE-2016-7429: Interface selection denial of service (DoS)

  - CVE-2016-9311: Trap crash

  - CVE-2016-9310: Mode 6 unauthenticated trap information disclosure and DDoS vector");

  script_tag(name:"affected", value:"NTPsec versions prior to 0.9.5.");

  script_tag(name:"solution", value:"Update to version 0.9.5 or later.");

  script_xref(name:"URL", value:"https://blog.ntpsec.org/2016/11/24/version-0-9-5.html");
  script_xref(name:"URL", value:"https://gitlab.com/NTPsec/ntpsec/-/blob/0539c4c9f53601166aa2c2a9f5d048e20b6636f4/NEWS.adoc#user-content-2016-11-23-0-9-5");

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

if (version_is_less(version: version, test_version: "0.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.5", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);

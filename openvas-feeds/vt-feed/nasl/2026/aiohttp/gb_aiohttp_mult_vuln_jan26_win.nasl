# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aio-libs_project:aiohttp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.156097");
  script_version("2026-01-08T05:48:01+0000");
  script_tag(name:"last_modification", value:"2026-01-08 05:48:01 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-07 05:00:56 +0000 (Wed, 07 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-69223", "CVE-2025-69224", "CVE-2025-69225", "CVE-2025-69226",
                "CVE-2025-69227", "CVE-2025-69228", "CVE-2025-69229", "CVE-2025-69230");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("aiohttp < 3.13.3 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_aiohttp_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("aio-libs_project/aiohttp/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"aiohttp is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-69223: HTTP Parser auto_decompress feature susceptible to zip bomb

  - CVE-2025-69224: Unicode processing of header values could cause parsing discrepancies

  - CVE-2025-69225: Unicode match groups in regexes for ASCII protocol elements

  - CVE-2025-69226: Brute-force leak of internal static file path components

  - CVE-2025-69227: Denial of service (DoS) when bypassing asserts

  - CVE-2025-69228: Denial of service (DoS) through large payloads

  - CVE-2025-69229: Denial of service (DoS) through chunked messages

  - CVE-2025-69230: Cookie parser warning storm");

  script_tag(name:"affected", value:"aiohttp prior to version 3.13.3.");

  script_tag(name:"solution", value:"Update to version 3.13.3 or later.");

  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-6mq8-rvhq-8wgg");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-69f9-5gxw-wvc2");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-mqqc-3gqh-h2x8");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-54jq-c3m8-4m76");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-jj3x-wxrx-4x23");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-6jhg-hg63-jvvf");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-g84x-mcqj-x9qq");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-fh55-r93g-j68g");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/01/05/14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.13.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.13.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

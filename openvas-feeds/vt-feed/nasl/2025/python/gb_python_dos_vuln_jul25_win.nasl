# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155052");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-07-30 04:56:24 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-8194");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python DoS Vulnerability (Jul 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a defect in the CPython 'tarfile' module affecting the
  'TarFile' extraction and entry enumeration APIs. The tar implementation would process tar
  archives with negative offsets without error, resulting in an infinite loop and deadlock during
  the parsing of maliciously crafted tar archives.");

  script_tag(name:"affected", value:"Python versions prior to 3.13.6.");

  script_tag(name:"solution", value:"Update to version 3.13.6 or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/ZULLF3IZ726XP5EY7XJ7YIN3K5MDYR2D/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/130577");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/137027");
  script_xref(name:"URL", value:"https://gist.github.com/sethmlarson/1716ac5b82b73dbcbf23ad2eff8b33e1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/29/1");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2025-11");
  # nb: The PSF seems to publish the affected / fixed versions in the "Product Status" part of
  # these since some time. So even it is a more generic link this should / will be always included.
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-8194");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.13.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.13.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

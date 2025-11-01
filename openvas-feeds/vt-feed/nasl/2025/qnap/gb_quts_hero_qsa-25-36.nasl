# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136100");
  script_version("2025-10-09T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-10-09 05:39:13 +0000 (Thu, 09 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-10-07 12:10:16 +0000 (Tue, 07 Oct 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-08 19:53:54 +0000 (Wed, 08 Oct 2025)");

  script_cve_id("CVE-2025-47211", "CVE-2025-47212", "CVE-2025-47213", "CVE-2025-48726",
                "CVE-2025-48727", "CVE-2025-48728", "CVE-2025-48729", "CVE-2025-48730",
                "CVE-2025-52424", "CVE-2025-52427", "CVE-2025-52429", "CVE-2025-52433",
                "CVE-2025-52853", "CVE-2025-52854", "CVE-2025-52855", "CVE-2025-52857",
                "CVE-2025-52858", "CVE-2025-52859", "CVE-2025-52860", "CVE-2025-52862",
                "CVE-2025-52866", "CVE-2025-53406", "CVE-2025-53407");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS Hero Multiple Vulnerabilities (QSA-25-36)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS Hero is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"QNAP QuTS Hero version h5.x prior to h5.2.6.3195 build
  20250715.

  Note: Due to the EOL status of h5.0.x and h5.1.x branches it is assumed that all h5.x versions are
  affected and not only the h5.2.x one as mentioned by the vendor.");

  script_tag(name:"solution", value:"Update to version h5.2.6.3195 build 20250715 or later.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-47211: A path traversal vulnerability

  - CVE-2025-47212: A command injection vulnerability

  - Multiple CVEs: NULL pointer dereference vulnerabilities resulting in a denial-of-service (DoS).

  - Multiple CVEs: Use of externally controlled format string vulnerabilities resulting
  in access to secrets and memory modification.

  Please see the references for more information on all CVEs.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-36");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/quts_hero/build");

if (version =~ "^h5\.") {
  if (version_is_less(version: version, test_version: "h5.2.6.3195")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.6.3195", fixed_build: "20250715");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.2.6.3195") &&
      (!build || version_is_less(version: build, test_version: "20250715"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.2.6.3195", fixed_build: "20250715");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155906");
  script_version("2025-12-02T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-12-02 05:40:47 +0000 (Tue, 02 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-01 07:43:42 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:C/A:C");

  script_cve_id("CVE-2023-30312");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("OpenWRT <= 24.10.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue allows off-path attackers to hijack TCP sessions,
  which could lead to a denial of service, impersonating the client to the server (e.g., for access
  to files over FTP), and impersonating the server to the client (e.g., to deliver false
  information from a finance website). This occurs because nf_conntrack_tcp_no_window_check is true
  by default.");

  script_tag(name:"affected", value:"OpenWRT version 24.10.4 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 01st December, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://blog.apnic.net/2024/06/18/off-path-tcp-hijacking-in-nat-enabled-wi-fi-networks/");
  script_xref(name:"URL", value:"https://www.ndss-symposium.org/ndss-paper/exploiting-sequence-number-leakage-tcp-hijacking-in-nat-enabled-wi-fi-networks/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "24.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

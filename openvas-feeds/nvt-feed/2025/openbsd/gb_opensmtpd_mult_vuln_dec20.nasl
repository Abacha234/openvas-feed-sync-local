# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125494");
  script_version("2025-11-14T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-11-14 05:39:48 +0000 (Fri, 14 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-12 14:30:00 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-29 18:42:35 +0000 (Tue, 29 Dec 2020)");

  script_cve_id("CVE-2020-35679", "CVE-2020-35680");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD < 6.8.0p1 Multiple Vulnerabilities (Dec 2020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-35679: A memory leak vulnerability in smtpd/table.c due to a missing
  regfree call allows attackers to trigger a very significant memory leak via
  messages to an instance that performs many regex lookups.

  - CVE-2020-35680: A NULL pointer dereference vulnerability in smtpd/lka_filter.c
  allows remote attackers to cause a denial of service (daemon crash) via a crafted
  pattern of client activity, because the filter state machine does not properly
  maintain the I/O channel between the SMTP engine and the filters layer.");

  script_tag(name:"affected", value:"OpenSMTPD prior to version 6.8.0p1.");

  script_tag(name:"solution", value:"Update to version 6.8.0p1 or later.");

  script_xref(name:"URL", value:"https://poolp.org/posts/2020-12-24/december-2020-opensmtpd-6.8.0p1-released-fixed-several-bugs-proposed-several-diffs-book-is-on-github/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.8.0p1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.0p1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

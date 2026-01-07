# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plex:plex_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.136785");
  script_version("2026-01-06T05:47:51+0000");
  script_tag(name:"last_modification", value:"2026-01-06 05:47:51 +0000 (Tue, 06 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-05 12:50:13 +0000 (Mon, 05 Jan 2026)");

  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2025-69414", "CVE-2025-69415", "CVE-2025-69416", "CVE-2025-69417");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Plex Media Server <= 1.43.0.10389 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("General");
  script_dependencies("gb_plex_media_server_http_detect.nasl");
  script_mandatory_keys("plex_media_server/detected");

  script_tag(name:"summary", value:"Plex Media Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-69414: Retrieval of a permanent access token via a /myplex/account call with a
  transient access token.

  - CVE-2025-69415: Ability to access /myplex/account with a device token is not properly aligned
  with whether the device is currently associated with an account.

  - CVE-2025-69416: In the plex.tv backend for Plex Media Server (PMS), a
  non-server device token can retrieve other tokens (intended for unrelated access) via
  clients.plex.tv/devices.xml.

  - CVE-2025-69417: In the plex.tv backend for Plex Media Server (PMS), a non-server device token
  can retrieve share tokens (intended for unrelated access) via a shared_servers endpoint.");

  script_tag(name:"affected", value:"Plex Media Server version 1.43.0.10389 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 05th January, 2026.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/lufinkey/vulnerability-research/blob/main/CVE-2025-34158/README.md");
  script_xref(name:"URL", value:"https://forums.plex.tv/t/plex-media-server/30447");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal( version: version, test_version_up: "1.43.0.10389")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

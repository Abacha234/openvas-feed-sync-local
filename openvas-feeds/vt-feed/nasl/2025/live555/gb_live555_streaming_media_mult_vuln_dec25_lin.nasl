# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:live555:streaming_media";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125585");
  script_version("2025-12-12T15:41:28+0000");
  script_tag(name:"last_modification", value:"2025-12-12 15:41:28 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-12-11 15:50:43 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-65404", "CVE-2025-65405", "CVE-2025-65406", "CVE-2025-65407",
                "CVE-2025-65408");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("LIVE555 Streaming Media 2018.09.02 Multiple DoS Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_live555_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("live555/streaming_media/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"LIVE555 Streaming Media is prone to multiple denial of service
  (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-65404: Buffer overflow in the getSideInfo2() function allows DoS via crafted MP3
  stream.

  - CVE-2025-65405: Use-after-free in ADTSAudioFileSource::samplingFrequency() function allows DoS
  via crafted ADTS/AAC file.

  - CVE-2025-65406: Heap overflow in MatroskaFile::createRTPSinkForTrackNumber() function allows DoS
  via crafted MKV file.

  - CVE-2025-65407: Use-after-free in MPEG1or2Demux::newElementaryStream() function allows DoS via
  crafted MPEG Program stream.

  - CVE-2025-65408: NULL pointer dereference in
  ADTSAudioFileServerMediaSubsession::createNewRTPSink() function allows DoS via crafted ADTS
  file.");

  script_tag(name:"affected", value:"LIVE555 Streaming Media version 2018.09.02.");

  script_tag(name:"solution", value:"No known solution is available as of 11th December, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://shimo.im/docs/16q8xMxpPlH8Z2q7");
  script_xref(name:"URL", value:"https://shimo.im/docs/25q5XMXpOwSr8w3D");
  script_xref(name:"URL", value:"https://shimo.im/docs/1lq7rMrp8lI1vW3e");
  script_xref(name:"URL", value:"https://shimo.im/docs/VMAPLVLpzZcZvoAg");
  script_xref(name:"URL", value:"https://shimo.im/docs/VMAPLVLp57SJ92Ag");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "2018.09.02")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

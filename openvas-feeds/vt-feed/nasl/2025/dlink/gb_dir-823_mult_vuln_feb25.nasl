# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-823_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171243");
  script_version("2025-10-17T18:17:07+0000");
  script_tag(name:"last_modification", value:"2025-10-17 18:17:07 +0000 (Fri, 17 Oct 2025)");
  script_tag(name:"creation_date", value:"2025-02-26 21:24:27 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-14 16:15:32 +0000 (Sun, 14 Sep 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2025-10401", "CVE-2025-25740", "CVE-2025-25741", "CVE-2025-25742",
                "CVE-2025-25743", "CVE-2025-25744", "CVE-2025-25745", "CVE-2025-25746",
                "CVE-2025-55848", "CVE-2025-11092", "CVE-2025-11095", "CVE-2025-11097",
                "CVE-2025-11098", "CVE-2025-11099", "CVE-2025-11100");

  script_name("D-Link DIR-823 Multiple Vulnerabilities (2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-823 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-10401: The affected element is an unknown function of the file /goform/diag_ping.
  Performing manipulation of the argument target_addr results in command injection. Remote
  exploitation of the attack is possible.

  - CVE-2025-25740: Stack-based buffer overflow vulnerability via the PSK parameter in the
  SetQuickVPNSettings module

  - CVE-2025-25741: Stack-based buffer overflow vulnerability via the IPv6_PppoePassword
  parameter in the SetIPv6PppoeSettings module

  - CVE-2025-25742: Stack-based buffer overflow vulnerability via the AccountPassword parameter
  in the SetSysEmailSettings module

  - CVE-2025-25743: Command injection vulnerability in the SetVirtualServerSettings module

  - CVE-2025-25744: Stack-based buffer overflow vulnerability via the Password parameter in the
  SetDynamicDNSSettings module

  - CVE-2025-25745: Stack-based buffer overflow vulnerability via the Password parameter in the
  SetQuickVPNSettings module

  - CVE-2025-25746: Stack-based buffer overflow vulnerability via the Password parameter in the
  SetWanSettings module

  - CVE-2025-55848: RCE vulnerability in the set_cassword settings interface, as the http_casswd
  parameter is not filtered by '&' to allow injection of reverse connection commands

  - CVE-2025-11092: Command injection vulnerability in the function sub_412E7C of the file
  /goform/set_switch_settings. Manipulation of the argument port causes command injection

  - CVE-2025-11095: Command injection vulnerability in the file /goform/delete_offline_device.
  Manipulation of the argument delvalue results in command injection

  - CVE-2025-11097: Command injection vulnerability in the file /goform/set_device_name.
  Manipulation of the argument mac leads to command injection

  - CVE-2025-11098: Command injection vulnerability in the file /goform/set_wifi_blacklists.
  Manipulation of the argument macList results in command injection

  - CVE-2025-11099: Command injection vulnerability in the function uci_del of the file
  /goform/delete_prohibiting. Manipulation of the argument delvalue causes command injection

  - CVE-2025-11100: Command injection vulnerability in the function uci_set of the file
  /goform/set_wifi_blacklists. Such manipulation leads to command injection");

  script_tag(name:"affected", value:"D-Link DIR-823 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-823 reached its End-of-Support Date in 31.03.2024, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10420");
  script_xref(name:"URL", value:"https://github.com/Cpppq43/D-Link/blob/main/D-Link%20DIR-823X%20AX3000.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://github.com/meigui637/iot_zone/blob/main/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md");
  script_xref(name:"URL", value:"https://github.com/maximdevere/CVE2/issues/4");
  script_xref(name:"URL", value:"https://github.com/n1ptune/dink/blob/main/delete_offline_device.md");
  script_xref(name:"URL", value:"https://github.com/n1ptune/dink/blob/main/set_device_name.md");
  script_xref(name:"URL", value:"https://github.com/n1ptune/dink/blob/main/set_wifi_blacklists.md");
  script_xref(name:"URL", value:"https://github.com/n1ptune/dink/blob/main/uci_del_in_delete_prohibiting.md");
  script_xref(name:"URL", value:"https://github.com/n1ptune/dink/blob/main/uci_set.md");



  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );

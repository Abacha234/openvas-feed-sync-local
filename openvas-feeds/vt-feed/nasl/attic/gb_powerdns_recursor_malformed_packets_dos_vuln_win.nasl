# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807393");
  script_version("2025-10-31T05:40:56+0000");
  script_cve_id("CVE-2014-3614");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-10-31 05:40:56 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-01-17 13:50:29 +0530 (Tue, 17 Jan 2017)");
  script_name("PowerDNS Recursor 3.6.0 Specific Sequence DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.

  Note: This VT has been deprecated as the product is not supported on Windows. It is therefore no
  longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  handling a specific sequence of packets which leads to  crash PowerDNS
  Recursor remotely.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 3.6.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 3.6.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q3/589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69778");
  script_xref(name:"URL", value:"https://blog.powerdns.com/2014/09/10/security-update-powerdns-recursor-3-6-1");
  script_xref(name:"URL", value:"http://doc.powerdns.com/html/changelog.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);


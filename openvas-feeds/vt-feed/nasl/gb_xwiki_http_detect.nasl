# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801840");
  script_version("2025-11-19T05:40:23+0000");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("XWiki Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of XWiki.");

  script_xref(name:"URL", value:"https://www.xwiki.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/xwiki/bin/login/XWiki/XWikiLogin";
install = "/xwiki";

res = http_get_cache(port: port, item: url);

# nb:
# - In some cases, /bin/view/Main/ also redirects but /xwiki/bin/login/XWiki/XWikiLogin replies with 4xx or 500
# - In some cases though, reply code is 401 but the version info can be extracted
if (res =~ "^HTTP/(1\.[01]|2) [45]" && "XWiki.XWikiLogin" >!< res) {
  url = "/bin/view/Main/";
  install = "/";

  res = http_get_cache(port: port, item: url);
}

# eg.
# - Finished setup: "Location: /bin/login/XWiki/XWikiLogin;jsessionid=452FF6C4CE36EB2F96F5D2AC41CE574A?srid=0xJAM7sf&xredirect=%2Fbin%2Fview%2Fxwiki%2Fbin%2Flogin%2FXWiki%2FXWikiLogin%2F%3Fsrid%3D0xJAM7sf"
# - Distribution Wizard: "Location: /bin/distribution/XWiki/Distribution?xredirect=%2Fbin%2Fview%2Fxwiki%2Fbin%2Flogin%2FXWiki%2FXWikiLogin%2F"
if (res =~ "^HTTP/1\.[01] 30." && res =~ "Location\s*:.*/bin/(login|distribution)/XWiki/(XWikiLogin|Distribution)") {
  redirect = eregmatch(pattern: '[Ll]ocation\\s*:.*(/bin/(login|distribution)/XWiki/(XWikiLogin|Distribution)[^\r\n]+)', string: res);
  if (redirect[1]) {
    url = redirect[1];
    res = http_get_cache(port: port, item: url);
    install = "/";
  }
}

if (("XWiki.XWikiLogin" >< res && "data-xwiki-wiki" >< res) ||

    # e.g. the following which has a 202 HTTP status code:
    # <p>XWiki is initializing (12%)...</p>
    # <title>XWiki is initializing (12%)...</title>
    res =~ "<(title|p)>XWiki is initializing[^<]+</(title|p)>" ||

    # nb: When version is extracted from /bin/view/Main/
    "xwiki:Main.WebHome" >< res ||

    # nb: Setup Wizard
    "<title>XWiki - XWiki - Distribution</title>" >< res) {

  version = "unknown";
  conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  # XWiki Enterprise 7.1.1
  # XWiki Debian 11.8.1
  # XWiki Enterprise Jetty HSQLDB 9.4
  # XWiki 11.10.10
  # XWiki Jetty HSQLDB 12.2
  vers = eregmatch(pattern: '"xwikiplatformversion">.*(XW|xw)iki[^0-9]+([0-9][-A-Za-z0-9.]+)', string: res);
  if (!isnull(vers[2]))
    version = vers[2];

  if (version == "unknown") {
    vers = eregmatch(pattern: "Powered by XWiki ([0-9.]+[-A-Za-z0-9]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  # nb:
  # - If the setup isn't finished yet
  # - This is only done for this one to prevent false positive version extraction on other pages
  if (version == "unknown" && "<title>XWiki - XWiki - Distribution</title>" >< res) {

    # e.g.:
    # <link rel='stylesheet' type='text/css' href='/bin/skin/resources/uicomponents/wizard/wizard.min.css?cache-version=1716989662000&#38;version=16.4.0'/>
    # <link rel='stylesheet' type='text/css' href='/bin/skin/resources/uicomponents/extension/distribution.min.css?cache-version=1716989662000&#38;version=16.4.0'/>
    #
    # nb: Version regex has been made more strict to expect at least a version like e.g. x.y.z to
    # prevent possible false positive version extraction
    vers = eregmatch(pattern: ";version=([0-9]+\.[0-9]+\.[-A-Za-z0-9]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "xwiki/detected", value: TRUE);
  set_kb_item(name: "xwiki/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([-A-Za-z0-9.]+)", base: "cpe:/a:xwiki:xwiki:");
  if (!cpe)
    cpe = "cpe:/a:xwiki:xwiki";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "XWiki", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl:conclurl),
              port: port);
  exit(0);
}

exit(0);

# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106757");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"creation_date", value:"2017-04-18 16:13:12 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PortlandLabs Concrete CMS / Concrete5 Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of PortlandLabs Concrete CMS (formerly
  Concrete5).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.concretecms.com/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20201203110840/https://www.concrete5.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);
if (!http_can_host_php(port: port))
  exit(0);

detection_patterns = make_list(
  # e.g.:
  #
  # <meta name="generator" content="concrete5 - 5.6.1" />
  # <meta name="generator" content="concrete5 - 5.6.3.4" />
  # <meta name="generator" content="concrete5 - 8.5.1"/>
  # <meta name="generator" content="concrete5 - 5.6.2.1" />
  # <meta name="generator" content="concrete5 - 5.5.2.1" />
  # <meta name="generator" content="concrete5 - 8.2.1"/>
  # <meta name="generator" content="concrete5 - 8.5.4"/>
  # <meta name="generator" content="concrete5 - 8.1.0"/>
  # <meta name="generator" content="concrete5"/>
  # <meta name="generator" content="concrete5 - 5.7.5.12"/><link rel="shortcut icon" href="https://<redacted>/favicon.ico" type="image/x-icon"/>
  #
  # and these:
  #
  # Set-Cookie: CONCRETE5=<redacted>; path=/
  # var CCM_IMAGE_PATH = "/concrete/images";
  # var CCM_REL = "";
  # <div id="ccm-logo"><img id="ccm-logo" src="/concrete/images/logo_menu.png" width="49" height="49" alt="concrete5" title="concrete5" /></div>
  #
  # Or for newer versions:
  #
  # <meta name="generator" content="Concrete CMS"/>
  # Set-Cookie: CONCRETE=<redacted>; path=/; HttpOnly
  # var CCM_IMAGE_PATH = "/concrete/images";
  # var CCM_REL = "";
  # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
  #
  # Note: See below for some additional examples which had exposed the version
  #
  '^\\s*<meta name="generator" content="(concrete5|Concrete CMS)[^"]*"',

  "^[Ss]et-[Cc]ookie\s*:\s*CONCRETE5?=",

  '^\\s*var CCM_IMAGE_PATH\\s*=\\s*"[^"]*"',
  '^\\s*var CCM_REL\\s*=\\s*"[^"]*"',

  'ccm-logo.+alt="[Cc]oncrete5?" title="[Cc]oncrete5?"'
);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php/login";
  res = http_get_cache(port: port, item: url);

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern (detection_patterns) {

    concl = egrep(string: res, pattern: pattern, icase: FALSE);
    if (concl) {

      found++;

      if (concluded)
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp(concl);
      concl = ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
      concluded += "  " + concl;
    }
  }

  if (found > 1) {

    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    version = "unknown";

    # nb: See examples above
    vers = eregmatch(pattern: "concrete5 - ([0-9.]+)", string: res, icase: FALSE);
    if (!isnull(vers[1])) {
      # nb: No need to add this to the concluded reporting
      version = vers[1];
    }

    # In some cases the version is also exposed like e.g.:
    #
    # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/updates/concrete-cms-9.1.2/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-8.5.12/concrete/images";
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.1.2/concrete/images";
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.1.3_remote_updater/concrete/images";
    # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/updates/concrete-cms-9.1.3_remote_updater/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
    # <div id="ccm-logo"><img id="ccm-logo" src="/updates/concrete5.6.2.1_updater/concrete/images/logo_menu.png" width="49" height="49" alt="concrete5" title="concrete5" /></div>
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.2.1_remote_updater/concrete/images";
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-8.5.16-remote-updater/concrete/images";
    # <li class="ccm-logo pull-left"><span><img id="ccm-logo" src="/updates/concrete-cms-8.5.16-remote-updater/concrete/images/logo.svg" alt="concrete5" title="concrete5"></span></li>
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.2.4_remote_updater/concrete/images";
    # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/updates/concrete-cms-9.2.4_remote_updater/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
    # var CCM_IMAGE_PATH = "/updates/concrete5.7.5.13_remote_updater/concrete/images";
    # <li class="ccm-logo pull-left"><span><img id="ccm-logo" src="/updates/concrete5.7.5.13_remote_updater/concrete/images/logo.png" width="23" height="23" alt="concrete5" title="concrete5" /></span></li>
    # <div id="ccm-logo"><img id="ccm-logo" src="/updates/concrete5.6.4.0/concrete/images/logo_menu.png" width="49" height="49" alt="concrete5" title="concrete5" /></div>
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.4.3/concrete/images";
    # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/updates/concrete-cms-9.4.3/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
    # var CCM_IMAGE_PATH = "/updates/concrete-cms-9.4.4/concrete/images";
    # <li class="ccm-logo float-start"><span><img id="ccm-logo" src="/updates/concrete-cms-9.4.4/concrete/images/logo.svg" alt="Concrete" title="Concrete"></span></li>
    # var CCM_IMAGE_PATH = "/updates/concrete5-8.5.7/concrete/images";
    # <li class="ccm-logo pull-left"><span><img id="ccm-logo" src="/updates/concrete5-8.5.7/concrete/images/logo.svg" alt="concrete5" title="concrete5"></span></li>
    # <div id="ccm-logo"><img id="ccm-logo" src="/updates/concrete5.6.3.3.ja/concrete/images/logo_menu.png" width="49" height="49" alt="concrete5" title="concrete5" /></div>
    if (version == "unknown") {
      # nb:
      # - Version regex was made a little bit more strict to not match something wrongly
      # - concrete5-8.5.7 -> This was version 8.5.7
      # - concrete5.7.5.13 -> This was version 5.7.5.13 as the same system also had
      #   "concrete5 - 5.7.5.13" in the generator tag
      vers = eregmatch(pattern: "/updates/concrete(-cms-|5-)?([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)[^/]*/concrete/", string: res, icase: FALSE);
      if (!isnull(vers[2])) {
        version = vers[2];
        concluded += '\n  ' + vers[0];
      }
    }

    set_kb_item(name: "concrete_cms/detected", value: TRUE);
    set_kb_item(name: "concrete_cms/http/detected", value: TRUE);

    cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:concretecms:concrete_cms:");
    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:concrete5:concrete5:");
    if (!cpe1) {
      cpe1 = "cpe:/a:concretecms:concrete_cms";
      cpe2 = "cpe:/a:concrete5:concrete5";
    }

    register_product(cpe: cpe1, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "PortlandLabs Concrete CMS / Concrete5", version: version, install: install, cpe: cpe1,
                                             concluded: concluded, concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);

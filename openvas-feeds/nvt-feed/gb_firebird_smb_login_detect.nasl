# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800851");
  script_version("2025-12-05T15:41:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-12-05 15:41:30 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");

  script_tag(name:"qod_type", value:"registry");

  script_name("Firebird SQL Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Firebird SQL.");

  script_xref(name:"URL", value:"https://www.firebirdsql.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

if (!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if (registry_key_exists(key:"SOFTWARE\Firebird Project\Firebird Server") ||
    registry_key_exists(key:"SOFTWARE\Wow6432Node\Firebird Project\Firebird Server")) {
  if ("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
  } else if("x64" >< os_arch) {
    key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                          "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
  }

  if (isnull(key_list))
    exit(0);

  foreach key (key_list) {
    foreach item (registry_enum_keys(key: key)) {
      app_name = registry_get_sz(key: key + item, item: "DisplayName");
      if (app_name =~ "Firebird [0-9.]+") {
        version = "unknown";
        reg_version = registry_get_sz(key: key + item, item: "DisplayVersion");
        insloc = registry_get_sz(key: key + item, item: "InstallLocation");

        concluded = "Registry Key:   " + key + item + '\n';
        concluded += "DisplayName:    " + app_name;
        if (reg_version) {
          version = reg_version;
          concluded += '\nDisplayVersion: ' + reg_version;
        }

        if (!reg_version) {
          path = insloc;
          file = "fbserver.exe";
          vers = fetch_file_version(sysPath: path, file_name: file);
          if (!vers) {
            path += "bin";
            vers = fetch_file_version(sysPath: path, file_name: file);
          }

          if (vers) {
            version = vers;
            concluded += '\nFileversion:    ' + version + ' fetched from ' + path + file;
          }
        }

        if (version) {
          set_kb_item(name: "firebird/sql/detected", value: TRUE);
          set_kb_item(name: "firebird/sql/smb-login/detected", value: TRUE);

          cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:firebirdsql:firebird:");
          if (!cpe)
            cpe = "cpe:/a:firebirdsql:firebird";

          register_product(cpe: cpe, location: insloc, port: 0, service: "smb-login");

          log_message(data: build_detection_report(app: "Firebird SQL", version: version, install: insloc,
                                                   cpe: cpe, concluded: concluded),
                      port: 0);
        }
      }
    }
  }
}

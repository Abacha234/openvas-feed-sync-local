# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900165");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4762");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("freeSSHd SFTP 'rename' and 'realpath' < 1.2.6 Remote DoS Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121184058/http://www.securityfocus.com/bid/31872");
  script_xref(name:"URL", value:"https://web.archive.org/web/20100215165634/http://milw0rm.com/exploits/6800");
  script_xref(name:"URL", value:"https://web.archive.org/web/20101009203548/http://secunia.com/advisories/32366/");

  script_tag(name:"summary", value:"freeSSHd SSH server is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"insight", value:"NULL pointer de-referencing errors in SFTP 'rename' and
  'realpath' commands. These can be exploited by passing overly long string passed as an argument to
  the affected commands.");

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service.");

  script_tag(name:"affected", value:"freeSSHd version 1.2.1.14 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 1.2.6 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

sshdPath = registry_get_sz(key:"SYSTEM\CurrentControlSet\Services\FreeSSHDService", item:"ImagePath");
if(!sshdPath)
  exit(0);

if(!fileVer = GetVersionFromFile(file:sshdPath))
  exit(0);

if(version_is_less(version:fileVer, test_version:"1.2.6")) {
  report = report_fixed_ver(installed_version:fileVer, fixed_version:"1.2.6", file_checked:sshdPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125544");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"creation_date", value:"2025-11-28 08:16:41 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-19 02:15:27 +0000 (Wed, 19 Mar 2025)");

  script_cve_id("CVE-2024-10441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) RCE Vulnerability (Synology-SA-24:20) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a remote code
  execution (RCE) vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Synology DiskStation Manager (DSM) RCE
  Vulnerability (Synology-SA-24:20) - Remote Known Vulnerable Versions Check' (OID:
  1.3.6.1.4.1.25623.1.0.170912).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper encoding or escaping of output vulnerability in the
  system plugin daemon allows remote attackers to execute arbitrary code via unspecified
  vectors.");

  script_tag(name:"affected", value:"Synology DSM version 7.2 prior to 7.2-64570-4, 7.2.1 prior
  to 7.2.1-69057-6 and 7.2.2 prior to 7.2.2-72806-1.");

  script_tag(name:"solution", value:"Update to version 7.2-64570-4, 7.2.1-69057-6, 7.2.2-72806-1
  or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_20");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

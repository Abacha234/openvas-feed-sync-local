# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840475");
  script_cve_id("CVE-2010-0834");
  script_tag(name:"creation_date", value:"2010-08-06 08:34:50 +0000 (Fri, 06 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-968-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-968-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-968-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'base-files' package(s) announced via the USN-968-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Ubuntu image shipped on some Dell Latitude
2110 systems was accidentally configured to allow unauthenticated package
installations. A remote attacker intercepting network communications or
a malicious archive mirror server could exploit this to trick the user
into installing unsigned packages, resulting in arbitrary code execution
with root privileges.");

  script_tag(name:"affected", value:"'base-files' package(s) on Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

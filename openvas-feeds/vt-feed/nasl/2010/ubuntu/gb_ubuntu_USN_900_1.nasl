# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840389");
  script_cve_id("CVE-2009-1904", "CVE-2009-4124", "CVE-2009-4492");
  script_tag(name:"creation_date", value:"2010-02-19 12:38:15 +0000 (Fri, 19 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-900-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-900-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-900-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9' package(s) announced via the USN-900-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanouel Kellinis discovered that Ruby did not properly handle certain
string operations. An attacker could exploit this issue and possibly
execute arbitrary code with application privileges. (CVE-2009-4124)

Giovanni Pellerano, Alessandro Tanasi, and Francesco Ongaro discovered that
Ruby did not properly sanitize data written to log files. An attacker could
insert specially-crafted data into log files which could affect certain
terminal emulators and cause arbitrary files to be overwritten, or even
possibly execute arbitrary commands. (CVE-2009-4492)

It was discovered that Ruby did not properly handle string arguments that
represent large numbers. An attacker could exploit this and cause a denial
of service. This issue only affected Ubuntu 9.10. (CVE-2009-1904)");

  script_tag(name:"affected", value:"'ruby1.9' package(s) on Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

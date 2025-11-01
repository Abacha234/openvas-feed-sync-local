# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840525");
  script_cve_id("CVE-2010-3847", "CVE-2010-3856");
  script_tag(name:"creation_date", value:"2010-10-26 07:06:02 +0000 (Tue, 26 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1009-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1009-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-1009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered multiple flaws in the GNU C Library's handling
of the LD_AUDIT environment variable when running a privileged binary. A
local attacker could exploit this to gain root privileges. (CVE-2010-3847,
CVE-2010-3856)");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

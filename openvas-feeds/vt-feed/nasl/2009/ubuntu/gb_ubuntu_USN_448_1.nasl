# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840132");
  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-448-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-448-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-448-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype, libxfont, xorg, xorg-server' package(s) announced via the USN-448-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sean Larsson of iDefense Labs discovered that the MISC-XC extension of
Xorg did not correctly verify the size of allocated memory. An
authenticated user could send a specially crafted X11 request and
execute arbitrary code with root privileges. (CVE-2007-1003)

Greg MacManus of iDefense Labs discovered that the BDF font handling
code in Xorg and FreeType did not correctly verify the size of allocated
memory. If a user were tricked into using a specially crafted font, a
remote attacker could execute arbitrary code with root privileges.
(CVE-2007-1351, CVE-2007-1352)");

  script_tag(name:"affected", value:"'freetype, libxfont, xorg, xorg-server' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

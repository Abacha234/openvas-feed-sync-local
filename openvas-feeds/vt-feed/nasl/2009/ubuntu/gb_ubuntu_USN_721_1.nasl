# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63413");
  script_tag(name:"creation_date", value:"2009-02-18 22:13:28 +0000 (Wed, 18 Feb 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-721-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-721-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/323327");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fglrx-installer' package(s) announced via the USN-721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marko Lindqvist discovered that the fglrx installer created an unsafe
LD_LIBRARY_PATH on 64bit systems. If a user were tricked into downloading
specially crafted libraries and running commands in the same directory,
a remote attacker could execute arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'fglrx-installer' package(s) on Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

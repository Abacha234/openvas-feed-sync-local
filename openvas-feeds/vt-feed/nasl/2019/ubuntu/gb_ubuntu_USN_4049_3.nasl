# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844124");
  script_tag(name:"creation_date", value:"2019-08-06 02:00:34 +0000 (Tue, 06 Aug 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4049-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4049-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4049-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1838890");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the USN-4049-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4049-1 fixed a vulnerability in GLib. The update introduced a regression
in Ubuntu 16.04 LTS causing a possibly memory leak. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that GLib created directories and files without properly
 restricting permissions. An attacker could possibly use this issue to access
 sensitive information.");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

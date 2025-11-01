# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845114");
  script_tag(name:"creation_date", value:"2021-10-26 01:00:57 +0000 (Tue, 26 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5122-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5122-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1948657");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-5122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apport could be tricked into writing core files as
root into arbitrary directories in certain scenarios. A local attacker
could possibly use this issue to escalate privileges. This update will
cause Apport to generate all core files in the /var/lib/apport/coredump
directory.");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

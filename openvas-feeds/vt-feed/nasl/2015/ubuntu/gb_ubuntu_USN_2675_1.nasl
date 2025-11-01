# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842378");
  script_cve_id("CVE-2015-1331", "CVE-2015-1334");
  script_tag(name:"creation_date", value:"2015-07-23 04:27:57 +0000 (Thu, 23 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Ubuntu: Security Advisory (USN-2675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2675-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2675-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the USN-2675-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered that LXC had a directory traversal flaw when creating
lock files. A local attacker could exploit this flaw to create an arbitrary
file as the root user. (CVE-2015-1331)

Roman Fiedler discovered that LXC incorrectly trusted the container's proc
filesystem to set up AppArmor profile changes and SELinux domain transitions. A
local attacker could exploit this flaw to run programs inside the container
that are not confined by AppArmor or SELinux. (CVE-2015-1334)");

  script_tag(name:"affected", value:"'lxc' package(s) on Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

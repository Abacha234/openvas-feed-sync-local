# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840382");
  script_cve_id("CVE-2009-4013", "CVE-2009-4014", "CVE-2009-4015");
  script_tag(name:"creation_date", value:"2010-01-29 13:09:25 +0000 (Fri, 29 Jan 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-891-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-891-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lintian' package(s) announced via the USN-891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Raphael Geissert discovered that lintian did not correctly validate
certain filenames when processing input. If a user or an automated system
were tricked into running lintian on a specially crafted set of files,
a remote attacker could execute arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'lintian' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

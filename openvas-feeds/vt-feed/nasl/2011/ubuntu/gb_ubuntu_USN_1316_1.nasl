# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840850");
  script_cve_id("CVE-2011-0764");
  script_tag(name:"creation_date", value:"2011-12-23 05:05:31 +0000 (Fri, 23 Dec 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1316-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1316-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1316-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 't1lib' package(s) announced via the USN-1316-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jonathan Brossard discovered that t1lib did not correctly handle certain
malformed font files. If a user were tricked into using a specially crafted
font file, a remote attacker could cause t1lib to crash or possibly execute
arbitrary code with user privileges.");

  script_tag(name:"affected", value:"'t1lib' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

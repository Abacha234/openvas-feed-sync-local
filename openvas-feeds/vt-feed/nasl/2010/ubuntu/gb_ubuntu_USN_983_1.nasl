# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840491");
  script_cve_id("CVE-2010-2956");
  script_tag(name:"creation_date", value:"2010-09-10 12:21:00 +0000 (Fri, 10 Sep 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-983-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-983-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Markus Wuethrich discovered that sudo did not always verify the user when a
group was specified in the Runas_Spec. A local attacker could exploit this
to execute arbitrary code as root if sudo was configured to allow the
attacker to use a program as a group when the attacker was not a part of
that group.");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

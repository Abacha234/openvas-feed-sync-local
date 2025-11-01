# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840452");
  script_cve_id("CVE-2010-1646");
  script_tag(name:"creation_date", value:"2010-07-02 12:26:21 +0000 (Fri, 02 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-956-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-956-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Evan Broder and Anders Kaseorg discovered that sudo did not properly
sanitize its environment when configured to use secure_path (the default in
Ubuntu). A local attacker could exploit this to execute arbitrary code as
root if sudo was configured to allow the attacker to use a program that
interpreted the PATH environment variable.");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

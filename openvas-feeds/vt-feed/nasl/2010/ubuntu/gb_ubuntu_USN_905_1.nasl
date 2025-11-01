# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840395");
  script_cve_id("CVE-2010-0426", "CVE-2010-0427");
  script_tag(name:"creation_date", value:"2010-03-02 07:46:47 +0000 (Tue, 02 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-905-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-905-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that sudo did not properly validate the path for the
'sudoedit' pseudo-command. A local attacker could exploit this to execute
arbitrary code as root if sudo was configured to allow the attacker to use
sudoedit. The sudoedit pseudo-command is not used in the default
installation of Ubuntu. (CVE-2010-0426)

It was discovered that sudo did not reset group permissions when the
'runas_default' configuration option was used. A local attacker could
exploit this to escalate group privileges if sudo was configured to allow
the attacker to run commands under the runas_default account. The
runas_default configuration option is not used in the default installation
of Ubuntu. This issue affected Ubuntu 8.04 LTS, 8.10 and 9.04.
(CVE-2010-0427)");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

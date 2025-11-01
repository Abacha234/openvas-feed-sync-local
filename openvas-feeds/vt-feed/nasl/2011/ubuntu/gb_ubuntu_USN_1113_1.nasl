# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840648");
  script_cve_id("CVE-2009-2939", "CVE-2011-0411");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1113-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1113-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix' package(s) announced via the USN-1113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Postfix package incorrectly granted write access
on the PID directory to the postfix user. A local attacker could use this
flaw to possibly conduct a symlink attack and overwrite arbitrary files.
This issue only affected Ubuntu 6.06 LTS and 8.04 LTS. (CVE-2009-2939)

Wietse Venema discovered that Postfix incorrectly handled cleartext
commands after TLS is in place. A remote attacker could exploit this to
inject cleartext commands into TLS sessions, and possibly obtain
confidential information such as passwords. (CVE-2011-0411)");

  script_tag(name:"affected", value:"'postfix' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

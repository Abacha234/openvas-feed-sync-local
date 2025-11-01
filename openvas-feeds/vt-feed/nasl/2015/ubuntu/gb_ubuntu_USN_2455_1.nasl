# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842071");
  script_cve_id("CVE-2014-7844");
  script_tag(name:"creation_date", value:"2015-01-23 11:59:19 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 16:05:00 +0000 (Tue, 21 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-2455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2455-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2455-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bsd-mailx' package(s) announced via the USN-2455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that bsd-mailx contained a feature that allowed
syntactically valid email addresses to be treated as shell commands. A
remote attacker could possibly use this issue with a valid email address to
execute arbitrary commands.

This functionality has now been disabled by default, and can be re-enabled
with the 'expandaddr' configuration option. This update alone does not
remove all possibilities of command execution. In environments where
scripts use mailx to process arbitrary email addresses, it is recommended
to modify them to use a '--' separator before the address to properly
handle those that begin with '-'. In addition, specifying sendmail options
after the '--' separator is no longer supported, existing scripts may need
to be modified to use the '-a' option instead.");

  script_tag(name:"affected", value:"'bsd-mailx' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

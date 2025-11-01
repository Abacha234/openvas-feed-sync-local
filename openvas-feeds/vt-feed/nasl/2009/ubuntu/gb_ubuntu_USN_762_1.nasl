# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63897");
  script_cve_id("CVE-2009-1300");
  script_tag(name:"creation_date", value:"2009-04-28 18:40:12 +0000 (Tue, 28 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-762-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-762-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/356012");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/356012");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt' package(s) announced via the USN-762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexandre Martani discovered that the APT daily cron script did not check
the return code of the date command. If a machine is configured for
automatic updates and is in a time zone where DST occurs at midnight, under
certain circumstances automatic updates might not be applied and could
become permanently disabled. (CVE-2009-1300)

Michael Casadevall discovered that APT did not properly verify repositories
signed with a revoked or expired key. If a repository were signed with only
an expired or revoked key and the signature was otherwise valid, APT would
consider the repository valid. ([link moved to references])");

  script_tag(name:"affected", value:"'apt' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

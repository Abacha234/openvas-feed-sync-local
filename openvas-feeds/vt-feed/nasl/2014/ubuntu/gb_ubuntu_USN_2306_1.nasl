# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841918");
  script_cve_id("CVE-2013-4357", "CVE-2013-4458", "CVE-2014-0475", "CVE-2014-4043");
  script_tag(name:"creation_date", value:"2014-08-05 11:20:59 +0000 (Tue, 05 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:31:00 +0000 (Tue, 14 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-2306-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2306-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2306-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc' package(s) announced via the USN-2306-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maksymilian Arciemowicz discovered that the GNU C Library incorrectly
handled the getaddrinfo() function. An attacker could use this issue to
cause a denial of service. This issue only affected Ubuntu 10.04 LTS.
(CVE-2013-4357)

It was discovered that the GNU C Library incorrectly handled the
getaddrinfo() function. An attacker could use this issue to cause a denial
of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
(CVE-2013-4458)

Stephane Chazelas discovered that the GNU C Library incorrectly handled
locale environment variables. An attacker could use this issue to possibly
bypass certain restrictions such as the ForceCommand restrictions in
OpenSSH. (CVE-2014-0475)

David Reid, Glyph Lefkowitz, and Alex Gaynor discovered that the GNU C
Library incorrectly handled posix_spawn_file_actions_addopen() path
arguments. An attacker could use this issue to cause a denial of service.
(CVE-2014-4043)");

  script_tag(name:"affected", value:"'eglibc' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843681");
  script_cve_id("CVE-2016-1580");
  script_tag(name:"creation_date", value:"2018-10-26 04:06:16 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-19 16:08:00 +0000 (Thu, 19 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-2956-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2956-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2956-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubuntu-core-launcher' package(s) announced via the USN-2956-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zygmunt Krynicki discovered that ubuntu-core-launcher did not properly
sanitize its input and contained a logic error when determining the
mountpoint of bind mounts when using snaps on Ubuntu classic systems (eg,
traditional desktop and server). If a user were tricked into installing a
malicious snap with a crafted snap name, an attacker could perform a
delayed attack to steal data or execute code within the security context of
another snap. This issue did not affect Ubuntu Core systems.");

  script_tag(name:"affected", value:"'ubuntu-core-launcher' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

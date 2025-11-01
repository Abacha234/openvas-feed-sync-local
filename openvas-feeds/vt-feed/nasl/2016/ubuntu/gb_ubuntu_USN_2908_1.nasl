# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842656");
  script_cve_id("CVE-2013-4312", "CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576", "CVE-2016-2069");
  script_tag(name:"creation_date", value:"2016-02-23 05:26:08 +0000 (Tue, 23 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:59:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-2908-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2908-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2908-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2908-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"halfdog discovered that OverlayFS, when mounting on top of a FUSE mount,
incorrectly propagated file attributes, including setuid. A local
unprivileged attacker could use this to gain privileges. (CVE-2016-1576)

halfdog discovered that OverlayFS in the Linux kernel incorrectly
propagated security sensitive extended attributes, such as POSIX ACLs. A
local unprivileged attacker could use this to gain privileges.
(CVE-2016-1575)

It was discovered that the Linux kernel did not properly enforce rlimits
for file descriptors sent over UNIX domain sockets. A local attacker could
use this to cause a denial of service. (CVE-2013-4312)

It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
implementation did not handle initial zero length segments properly. A
local attacker could use this to cause a denial of service (unkillable
task). (CVE-2015-8785)

Andy Lutomirski discovered a race condition in the Linux kernel's
translation lookaside buffer (TLB) handling of flush events. A local
attacker could use this to cause a denial of service or possibly leak
sensitive information. (CVE-2016-2069)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

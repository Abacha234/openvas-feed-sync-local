# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841891");
  script_cve_id("CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533");
  script_tag(name:"creation_date", value:"2014-07-15 11:31:14 +0000 (Tue, 15 Jul 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2275-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2275-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the USN-2275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alban Crequy discovered that dbus-daemon incorrectly sent AccessDenied
errors to the service instead of the client when enforcing permissions. A
local user can use this issue to possibly deny access to the service.
(CVE-2014-3477)

Alban Crequy discovered that dbus-daemon incorrectly handled certain file
descriptors. A local attacker could use this issue to cause services or
clients to disconnect, resulting in a denial of service. (CVE-2014-3532,
CVE-2014-3533)");

  script_tag(name:"affected", value:"'dbus' package(s) on Ubuntu 12.04, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

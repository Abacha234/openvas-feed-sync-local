# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842438");
  script_cve_id("CVE-2015-1319");
  script_tag(name:"creation_date", value:"2015-09-17 04:18:57 +0000 (Thu, 17 Sep 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2741-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2741-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2741-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unity-settings-daemon' package(s) announced via the USN-2741-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Unity Settings Daemon incorrectly allowed
removable media to be mounted when the screen is locked. If a vulnerability
were discovered in some other desktop component, such as an image library,
a local attacker could possibly use this issue to gain access to the
session.");

  script_tag(name:"affected", value:"'unity-settings-daemon' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

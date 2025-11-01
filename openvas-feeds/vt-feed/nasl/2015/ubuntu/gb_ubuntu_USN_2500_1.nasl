# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842093");
  script_cve_id("CVE-2013-6424", "CVE-2015-0255");
  script_tag(name:"creation_date", value:"2015-02-18 04:41:57 +0000 (Wed, 18 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2500-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2500-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2500-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server, xorg-server-lts-trusty, xorg-server-lts-utopic' package(s) announced via the USN-2500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Olivier Fourdan discovered that the X.Org X server incorrectly handled
XkbSetGeometry requests resulting in an information leak. An attacker able
to connect to an X server, either locally or remotely, could use this issue
to possibly obtain sensitive information. (CVE-2015-0255)

It was discovered that the X.Org X server incorrectly handled certain
trapezoids. An attacker able to connect to an X server, either locally or
remotely, could use this issue to possibly crash the server. This issue
only affected Ubuntu 12.04 LTS. (CVE-2013-6424)");

  script_tag(name:"affected", value:"'xorg-server, xorg-server-lts-trusty, xorg-server-lts-utopic' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

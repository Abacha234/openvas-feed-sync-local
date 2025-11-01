# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844171");
  script_tag(name:"creation_date", value:"2019-09-11 02:00:58 +0000 (Wed, 11 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4120-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4120-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4120-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1842651");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the USN-4120-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4120-1 fixed a vulnerability in systemd. The update included a recent
SRU from the updates pocket that introduced networking problems for some
users. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the systemd-resolved D-Bus interface did not
 enforce appropriate access controls. A local unprivileged user could
 exploit this to modify a system's DNS resolver settings.");

  script_tag(name:"affected", value:"'systemd' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

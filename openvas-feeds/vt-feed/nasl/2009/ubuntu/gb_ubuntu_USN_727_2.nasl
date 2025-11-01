# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63507");
  script_cve_id("CVE-2009-0365");
  script_tag(name:"creation_date", value:"2009-03-07 20:47:03 +0000 (Sat, 07 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-727-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-727-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-727-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'network-manager' package(s) announced via the USN-727-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-727-1 fixed vulnerabilities in network-manager-applet. This advisory
provides the corresponding updates for NetworkManager.

It was discovered that NetworkManager did not properly enforce permissions when
responding to dbus requests. A local user could perform dbus queries to view
system and user network connection passwords and pre-shared keys.");

  script_tag(name:"affected", value:"'network-manager' package(s) on Ubuntu 6.06, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

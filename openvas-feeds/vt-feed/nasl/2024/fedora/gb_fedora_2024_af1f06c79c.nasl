# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887023");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-21501");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-07 06:35:21 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for glances (FEDORA-2024-af1f06c79c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-af1f06c79c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4EB5JPYRCTS64EA5AMV3INHDPI6I4AW7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glances'
  package(s) announced via the FEDORA-2024-af1f06c79c advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Glances is a cross-platform monitoring tool which aims to present a large
amount of monitoring information through a curses or Web based interface.
The information dynamically adapts depending on the size of the user interface

It can also work in client/server mode. Remote monitoring could be done via
terminal, Web interface or API (XML-RPC and RESTful). Stats can also be
exported to files or external time/value databases.

Glances is written in Python and uses libraries to grab information from your
system. It is based on an open architecture where developers can add new
plugins or exports modules.");

  script_tag(name:"affected", value:"'glances' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);

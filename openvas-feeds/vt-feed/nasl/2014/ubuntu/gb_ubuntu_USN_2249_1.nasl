# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841865");
  script_cve_id("CVE-2014-3801");
  script_tag(name:"creation_date", value:"2014-06-23 11:24:51 +0000 (Mon, 23 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2249-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2249-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heat' package(s) announced via the USN-2249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jason Dunsmore discovered that OpenStack heat did not properly restrict
access to template information. A remote authenticated attacker could
exploit this to see URL provider templates of other tenants for a limited
time.");

  script_tag(name:"affected", value:"'heat' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

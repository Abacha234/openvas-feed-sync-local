# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842031");
  script_cve_id("CVE-2014-3608", "CVE-2014-7230");
  script_tag(name:"creation_date", value:"2014-11-12 05:24:35 +0000 (Wed, 12 Nov 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2407-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2407-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2407-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-2407-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Garth Mollett discovered that OpenStack Nova did not properly clean up an
instance when using rescue mode with the VMWare driver. A remove
authenticated user could exploit this to bypass intended quota limits. By
default, Ubuntu does not use the VMWare driver. (CVE-2014-3608)

Amrith Kumar discovered that OpenStack Nova did not properly sanitize log
message contents. Under certain circumstances, a local attacker with read
access to Nova log files could obtain access to sensitive information.
(CVE-2014-7230)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

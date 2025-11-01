# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841093");
  script_cve_id("CVE-2010-4159", "CVE-2012-3382");
  script_tag(name:"creation_date", value:"2012-07-26 05:40:18 +0000 (Thu, 26 Jul 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1517-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1517-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mono' package(s) announced via the USN-1517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Mono System.Web library incorrectly filtered
certain error messages related to forbidden files. If a user were tricked
into opening a specially crafted URL, an attacker could possibly exploit
this to conduct cross-site scripting (XSS) attacks. (CVE-2012-3382)

It was discovered that the Mono System.Web library incorrectly handled the
EnableViewStateMac property. If a user were tricked into opening a
specially crafted URL, an attacker could possibly exploit this to conduct
cross-site scripting (XSS) attacks. This issue only affected Ubuntu
10.04 LTS. (CVE-2010-4159)");

  script_tag(name:"affected", value:"'mono' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841931");
  script_cve_id("CVE-2014-0032", "CVE-2014-3522", "CVE-2014-3528");
  script_tag(name:"creation_date", value:"2014-08-15 03:56:40 +0000 (Fri, 15 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2316-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2316-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2316-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the USN-2316-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lieven Govaerts discovered that the Subversion mod_dav_svn module
incorrectly handled certain request methods when SVNListParentPath was
enabled. A remote attacker could use this issue to cause the server to
crash, resulting in a denial of service. This issue only affected Ubuntu
12.04 LTS. (CVE-2014-0032)

Ben Reser discovered that Subversion did not correctly validate SSL
certificates containing wildcards. A remote attacker could exploit this to
perform a machine-in-the-middle attack to view sensitive information or alter
encrypted communications. (CVE-2014-3522)

Bert Huijben discovered that Subversion did not properly handle cached
credentials. A malicious server could possibly use this issue to obtain
credentials cached for a different server. (CVE-2014-3528)");

  script_tag(name:"affected", value:"'subversion' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

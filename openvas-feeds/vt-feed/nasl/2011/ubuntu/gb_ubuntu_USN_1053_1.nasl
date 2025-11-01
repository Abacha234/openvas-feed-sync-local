# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840580");
  script_cve_id("CVE-2007-2448", "CVE-2010-3315", "CVE-2010-4539", "CVE-2010-4644");
  script_tag(name:"creation_date", value:"2011-02-04 13:19:53 +0000 (Fri, 04 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1053-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1053-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the USN-1053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Subversion incorrectly handled certain 'partial
access' privileges in rare scenarios. Remote authenticated users could use
this flaw to obtain sensitive information (revision properties). This issue
only applied to Ubuntu 6.06 LTS. (CVE-2007-2448)

It was discovered that the Subversion mod_dav_svn module for Apache did not
properly handle a named repository as a rule scope. Remote authenticated
users could use this flaw to bypass intended restrictions. This issue only
applied to Ubuntu 9.10, 10.04 LTS, and 10.10. (CVE-2010-3315)

It was discovered that the Subversion mod_dav_svn module for Apache
incorrectly handled the walk function. Remote authenticated users could use
this flaw to cause the service to crash, leading to a denial of service.
(CVE-2010-4539)

It was discovered that Subversion incorrectly handled certain memory
operations. Remote authenticated users could use this flaw to consume large
quantities of memory and cause the service to crash, leading to a denial of
service. This issue only applied to Ubuntu 9.10, 10.04 LTS, and 10.10.
(CVE-2010-4644)");

  script_tag(name:"affected", value:"'subversion' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

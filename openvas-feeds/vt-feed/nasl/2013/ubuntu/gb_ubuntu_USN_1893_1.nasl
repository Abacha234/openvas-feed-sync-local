# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841492");
  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849", "CVE-2013-1884", "CVE-2013-1968", "CVE-2013-2112");
  script_tag(name:"creation_date", value:"2013-07-02 04:50:46 +0000 (Tue, 02 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1893-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1893-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the USN-1893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Klink discovered that the Subversion mod_dav_svn module for
Apache did not properly handle a large number of properties. A remote
authenticated attacker could use this flaw to cause memory consumption,
leading to a denial of service. (CVE-2013-1845)

Ben Reser discovered that the Subversion mod_dav_svn module for
Apache did not properly handle certain LOCKs. A remote authenticated
attacker could use this flaw to cause Subversion to crash, leading to a
denial of service. (CVE-2013-1846)

Philip Martin and Ben Reser discovered that the Subversion mod_dav_svn
module for Apache did not properly handle certain LOCKs. A remote
attacker could use this flaw to cause Subversion to crash, leading to a
denial of service. (CVE-2013-1847)

It was discovered that the Subversion mod_dav_svn module for Apache did not
properly handle certain PROPFIND requests. A remote attacker could use this
flaw to cause Subversion to crash, leading to a denial of service.
(CVE-2013-1849)

Greg McMullin, Stefan Fuhrmann, Philip Martin, and Ben Reser discovered
that the Subversion mod_dav_svn module for Apache did not properly handle
certain log REPORT requests. A remote attacker could use this flaw to cause
Subversion to crash, leading to a denial of service. This issue only
affected Ubuntu 12.10 and Ubuntu 13.04. (CVE-2013-1884)

Stefan Sperling discovered that Subversion incorrectly handled newline
characters in filenames. A remote authenticated attacker could use this
flaw to corrupt FSFS repositories. (CVE-2013-1968)

Boris Lytochkin discovered that Subversion incorrectly handled TCP
connections that were closed early. A remote attacker could use this flaw
to cause Subversion to crash, leading to a denial of service.
(CVE-2013-2112)");

  script_tag(name:"affected", value:"'subversion' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

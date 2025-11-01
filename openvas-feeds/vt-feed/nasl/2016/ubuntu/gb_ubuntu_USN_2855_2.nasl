# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842644");
  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-7540", "CVE-2015-8467");
  script_tag(name:"creation_date", value:"2016-02-17 05:27:45 +0000 (Wed, 17 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2855-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2855-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2855-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1545750");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-2855-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2855-1 fixed vulnerabilities in Samba. The upstream fix for
CVE-2015-5252 introduced a regression in certain specific environments.
This update fixes the problem.

Original advisory details:

 Thilo Uttendorfer discovered that the Samba LDAP server incorrectly handled
 certain packets. A remote attacker could use this issue to cause the LDAP
 server to stop responding, resulting in a denial of service. This issue
 only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10.
 (CVE-2015-3223)

 Jan Kasprzak discovered that Samba incorrectly handled certain symlinks. A
 remote attacker could use this issue to access files outside the exported
 share path. (CVE-2015-5252)

 Stefan Metzmacher discovered that Samba did not enforce signing when
 creating encrypted connections. If a remote attacker were able to perform a
 machine-in-the-middle attack, this flaw could be exploited to view sensitive
 information. (CVE-2015-5296)

 It was discovered that Samba incorrectly performed access control when
 using the VFS shadow_copy2 module. A remote attacker could use this issue
 to access snapshots, contrary to intended permissions. (CVE-2015-5299)

 Douglas Bagnall discovered that Samba incorrectly handled certain string
 lengths. A remote attacker could use this issue to possibly access
 sensitive information. (CVE-2015-5330)

 It was discovered that the Samba LDAP server incorrectly handled certain
 packets. A remote attacker could use this issue to cause the LDAP server to
 stop responding, resulting in a denial of service. This issue only affected
 Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10. (CVE-2015-7540)

 Andrew Bartlett discovered that Samba incorrectly checked administrative
 privileges during creation of machine accounts. A remote attacker could
 possibly use this issue to bypass intended access restrictions in certain
 environments. This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.04 and
 Ubuntu 15.10. (CVE-2015-8467)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840673");
  script_cve_id("CVE-2009-0887", "CVE-2010-3316", "CVE-2010-3430", "CVE-2010-3431", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-4706", "CVE-2010-4707");
  script_tag(name:"creation_date", value:"2011-06-06 14:56:27 +0000 (Mon, 06 Jun 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1140-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1140-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1140-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/790538");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-1140-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1140-1 fixed vulnerabilities in PAM. A regression was found that caused
cron to stop working with a 'Module is unknown' error. As a result, systems
configured with automatic updates will not receive updates until cron is
restarted, these updates are installed or the system is rebooted. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Marcus Granado discovered that PAM incorrectly handled configuration files
 with non-ASCII usernames. A remote attacker could use this flaw to cause a
 denial of service, or possibly obtain login access with a different users
 username. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-0887)

 It was discovered that the PAM pam_xauth, pam_env and pam_mail modules
 incorrectly handled dropping privileges when performing operations. A local
 attacker could use this flaw to read certain arbitrary files, and access
 other sensitive information. (CVE-2010-3316, CVE-2010-3430, CVE-2010-3431,
 CVE-2010-3435)

 It was discovered that the PAM pam_namespace module incorrectly cleaned the
 environment during execution of the namespace.init script. A local attacker
 could use this flaw to possibly gain privileges. (CVE-2010-3853)

 It was discovered that the PAM pam_xauth module incorrectly handled certain
 failures. A local attacker could use this flaw to delete certain unintended
 files. (CVE-2010-4706)

 It was discovered that the PAM pam_xauth module incorrectly verified
 certain file properties. A local attacker could use this flaw to cause a
 denial of service. (CVE-2010-4707)");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

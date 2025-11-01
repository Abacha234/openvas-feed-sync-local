# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68462");
  script_cve_id("CVE-2010-3714", "CVE-2010-3715", "CVE-2010-3716", "CVE-2010-3717", "CVE-2010-4068");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2121");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2121");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in TYPO3. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3714

Multiple remote file disclosure vulnerabilities in the jumpUrl mechanism and the Extension Manager allowed attackers to read files with the privileges of the account under which the web server was running.

CVE-2010-3715

The TYPO3 backend contained several cross-site scripting vulnerabilities, and the RemoveXSS function did not filter all Javascript code.

CVE-2010-3716

Malicious editors with user creation permission could escalate their privileges by creating new users in arbitrary groups, due to lack of input validation in the taskcenter.

CVE-2010-3717

TYPO3 exposed a crash bug in the PHP filter_var function, enabling attackers to cause the web server process to crash and thus consume additional system resources.

For the stable distribution (lenny), these problems have been fixed in version 4.2.5-1+lenny6.

For the unstable distribution (sid) and the upcoming stable distribution (squeeze), these problems have been fixed in version 4.3.7-1.

We recommend that you upgrade your TYPO3 packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
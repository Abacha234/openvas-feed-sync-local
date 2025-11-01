# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703008");
  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3597", "CVE-2014-4670");
  script_tag(name:"creation_date", value:"2014-08-20 22:00:00 +0000 (Wed, 20 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3008)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3008");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3008");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3008 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a general-purpose scripting language commonly used for web application development. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-3538

It was discovered that the original fix for CVE-2013-7345 did not sufficiently address the problem. A remote attacker could still cause a denial of service (CPU consumption) via a specially-crafted input file that triggers backtracking during processing of an awk regular expression rule.

CVE-2014-3587

It was discovered that the CDF parser of the fileinfo module does not properly process malformed files in the Composite Document File (CDF) format, leading to crashes.

CVE-2014-3597

It was discovered that the original fix for CVE-2014-4049 did not completely address the issue. A malicious server or man-in-the-middle attacker could cause a denial of service (crash) and possibly execute arbitrary code via a crafted DNS TXT record.

CVE-2014-4670

It was discovered that PHP incorrectly handled certain SPL Iterators. A local attacker could use this flaw to cause PHP to crash, resulting in a denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 5.4.4-14+deb7u13. In addition, this update contains several bugfixes originally targeted for the upcoming Wheezy point release.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702942");
  script_cve_id("CVE-2014-3941", "CVE-2014-3942", "CVE-2014-3943", "CVE-2014-3944", "CVE-2014-3945", "CVE-2014-3946");
  script_tag(name:"creation_date", value:"2014-05-31 22:00:00 +0000 (Sat, 31 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2942)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2942");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2942");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-001/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-2942 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in the Typo3 CMS. More information can be found in the upstream advisory: [link moved to references]

For the stable distribution (wheezy), this problem has been fixed in version 4.5.19+dfsg1-5+wheezy3.

For the testing distribution (jessie), this problem has been fixed in version 4.5.34+dfsg1-1.

For the unstable distribution (sid), this problem has been fixed in version 4.5.34+dfsg1-1.

We recommend that you upgrade your typo3-src packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
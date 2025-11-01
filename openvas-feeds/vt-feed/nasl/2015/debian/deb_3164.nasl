# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703164");
  script_cve_id("CVE-2015-2047");
  script_tag(name:"creation_date", value:"2015-02-20 23:00:00 +0000 (Fri, 20 Feb 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3164");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3164");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'typo3-src' package(s) announced via the DSA-3164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pierrick Caillon discovered that the authentication could be bypassed in the Typo 3 content management system. Please refer to the upstream advisory for additional information:

For the stable distribution (wheezy), this problem has been fixed in version 4.5.19+dfsg1-5+wheezy4.

The upcoming stable distribution (jessie) no longer includes Typo 3.

For the unstable distribution (sid), this problem has been fixed in version 4.5.40+dfsg1-1.

We recommend that you upgrade your typo3-src packages.");

  script_tag(name:"affected", value:"'typo3-src' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
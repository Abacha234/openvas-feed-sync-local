# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70547");
  script_cve_id("CVE-2011-2768", "CVE-2011-2769");
  script_tag(name:"creation_date", value:"2012-02-11 07:27:18 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2331)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2331");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2331");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DSA-2331 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered by frosty_un that a design flaw in Tor, an online privacy tool, allows malicious relay servers to learn certain information that they should not be able to learn. Specifically, a relay that a user connects to directly could learn which other relays that user is connected to directly. In combination with other attacks, this issue can lead to deanonymizing the user. The Common Vulnerabilities and Exposures project has assigned CVE-2011-2768 to this issue.

In addition to fixing the above mentioned issues, the updates to oldstable and stable fix a number of less critical issues ( CVE-2011-2769). Please see the posting from the Tor blog for more information.

For the oldstable distribution (lenny), this problem has been fixed in version 0.2.1.31-1~lenny+1. Due to technical limitations in the Debian archive scripts, the update cannot be released synchronously with the packages for stable. It will be released shortly.

For the stable distribution (squeeze), this problem has been fixed in version 0.2.1.31-1.

For the unstable (sid) and testing (wheezy) distributions, this problem has been fixed in version 0.2.2.34-1.

For the experimental distribution, this problem have has been fixed in version 0.2.3.6-alpha-1.

We recommend that you upgrade your tor packages.");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
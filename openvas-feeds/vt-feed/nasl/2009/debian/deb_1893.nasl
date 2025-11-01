# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64977");
  script_cve_id("CVE-2009-2632", "CVE-2009-3235");
  script_tag(name:"creation_date", value:"2009-09-28 17:09:13 +0000 (Mon, 28 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1893)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1893");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1893");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-imapd-2.2, kolab-cyrus-imapd' package(s) announced via the DSA-1893 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SIEVE component of cyrus-imapd and kolab-cyrus-imapd, the Cyrus mail system, is vulnerable to a buffer overflow when processing SIEVE scripts. This can be used to elevate privileges to the cyrus system user. An attacker who is able to install SIEVE scripts executed by the server is therefore able to read and modify arbitrary email messages on the system. The update introduced by DSA 1881-1 was incomplete and the issue has been given an additional CVE id due to its complexity.

For the oldstable distribution (etch), this problem has been fixed in version 2.2.13-10+etch4 for cyrus-imapd-2.2 and version 2.2.13-2+etch2 for kolab-cyrus-imapd.

For the stable distribution (lenny), this problem has been fixed in version 2.2.13-14+lenny3 for cyrus-imapd-2.2, version 2.2.13-5+lenny2 for kolab-cyrus-imapd.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.2.13-15 for cyrus-imapd-2.2, and will be fixed soon for kolab-cyrus-imapd.

We recommend that you upgrade your cyrus-imapd-2.2 and kolab-cyrus-imapd packages.");

  script_tag(name:"affected", value:"'cyrus-imapd-2.2, kolab-cyrus-imapd' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70696");
  script_cve_id("CVE-2011-3481");
  script_tag(name:"creation_date", value:"2012-02-11 08:25:02 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2377)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2377");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2377");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-imapd-2.2' package(s) announced via the DSA-2377 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that cyrus-imapd, a highly scalable mail system designed for use in enterprise environments, is not properly parsing mail headers when a client makes use of the IMAP threading feature. As a result, a NULL pointer is dereferenced which crashes the daemon. An attacker can trigger this by sending a mail containing crafted reference headers and access the mail with a client that uses the server threading feature of IMAP.

For the oldstable distribution (lenny), this problem has been fixed in version 2.2.13-14+lenny6.

For the stable distribution (squeeze), this problem has been fixed in version 2.2.13-19+squeeze3.

For the testing (wheezy) and unstable (sid) distributions, this problem has been fixed in cyrus-imapd-2.4 version 2.4.11-1.

We recommend that you upgrade your cyrus-imapd-2.2 packages.");

  script_tag(name:"affected", value:"'cyrus-imapd-2.2' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
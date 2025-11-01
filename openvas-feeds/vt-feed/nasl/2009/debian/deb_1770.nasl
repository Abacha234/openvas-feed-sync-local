# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63798");
  script_cve_id("CVE-2008-4182", "CVE-2009-0930");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1770)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1770");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1770");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imp4' package(s) announced via the DSA-1770 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in imp4, a webmail component for the horde framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4182

It was discovered that imp4 suffers from a cross-site scripting (XSS) attack via the user field in an IMAP session, which allows attackers to inject arbitrary HTML code.

CVE-2009-0930

It was discovered that imp4 is prone to several cross-site scripting (XSS) attacks via several vectors in the mail code allowing attackers to inject arbitrary HTML code.

For the oldstable distribution (etch), these problems have been fixed in version 4.1.3-4etch1.

For the stable distribution (lenny), these problems have been fixed in version 4.2-4, which was already included in the lenny release.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 4.2-4.

We recommend that you upgrade your imp4 packages.");

  script_tag(name:"affected", value:"'imp4' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
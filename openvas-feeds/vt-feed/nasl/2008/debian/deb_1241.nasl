# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57749");
  script_cve_id("CVE-2006-6142");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1241");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1241");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squirrelmail' package(s) announced via the DSA-1241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Martijn Brinkers discovered cross-site scripting vulnerabilities in the mailto parameter of webmail.php, the session and delete_draft parameters of compose.php and through a shortcoming in the magicHTML filter. An attacker could abuse these to execute malicious JavaScript in the user's webmail session.

Also, a workaround was made for Internet Explorer <= 5: IE will attempt to guess the MIME type of attachments based on content, not the MIME header sent. Attachments could fake to be a 'harmless' JPEG, while they were in fact HTML that Internet Explorer would render.

For the stable distribution (sarge) these problems have been fixed in version 2:1.4.4-10.

For the upcoming stable distribution (etch) these problems have been fixed in version 2:1.4.9a-1.

For the unstable distribution (sid) these problems have been fixed in version 2:1.4.9a-1.

We recommend that you upgrade your squirrelmail package.");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
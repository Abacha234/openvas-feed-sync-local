# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704674");
  script_cve_id("CVE-2020-12625", "CVE-2020-12626");
  script_tag(name:"creation_date", value:"2020-05-06 03:00:15 +0000 (Wed, 06 May 2020)");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4674)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4674");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4674");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/roundcube");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundcube' package(s) announced via the DSA-4674 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that roundcube, a skinnable AJAX based webmail solution for IMAP servers, did not correctly process and sanitize requests. This would allow a remote attacker to perform either a cross-site request forgery (CSRF) forcing an authenticated user to be logged out, or a cross-site scripting (XSS) leading to execution of arbitrary code.

For the oldstable distribution (stretch), these problems have been fixed in version 1.2.3+dfsg.1-4+deb9u4.

For the stable distribution (buster), these problems have been fixed in version 1.3.11+dfsg.1-1~deb10u1.

We recommend that you upgrade your roundcube packages.

For the detailed security status of roundcube please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'roundcube' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

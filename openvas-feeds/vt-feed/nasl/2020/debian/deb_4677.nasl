# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704677");
  script_cve_id("CVE-2020-11025", "CVE-2020-11026", "CVE-2020-11027", "CVE-2020-11028", "CVE-2020-11029");
  script_tag(name:"creation_date", value:"2020-05-07 03:00:28 +0000 (Thu, 07 May 2020)");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4677)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4677");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4677");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wordpress");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-4677 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web blogging tool. They allowed remote attackers to perform various cross-site scripting (XSS) and cross-site request forgery (CSRF) attacks, create files on the server, disclose private information, create open redirects, poison cache, and bypass authorization access and input sanitation.

For the oldstable distribution (stretch), these problems have been fixed in version 4.7.5+dfsg-2+deb9u6.

For the stable distribution (buster), these problems have been fixed in version 5.0.4+dfsg1-1+deb10u2.

We recommend that you upgrade your wordpress packages.

For the detailed security status of wordpress please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

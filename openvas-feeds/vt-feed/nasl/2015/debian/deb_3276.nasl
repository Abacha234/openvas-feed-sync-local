# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703276");
  script_cve_id("CVE-2015-4050");
  script_tag(name:"creation_date", value:"2015-05-30 22:00:00 +0000 (Sat, 30 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3276");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3276");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-3276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Zalas discovered that Symfony, a framework to create websites and web applications, was vulnerable to restriction bypass. It was affecting applications with ESI or SSI support enabled, that use the FragmentListener. A malicious user could call any controller via the /_fragment path by providing an invalid hash in the URL (or removing it), bypassing URL signing and security rules.

For the stable distribution (jessie), this problem has been fixed in version 2.3.21+dfsg-4+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 2.7.0~beta2+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in version 2.7.0~beta2+dfsg-2.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
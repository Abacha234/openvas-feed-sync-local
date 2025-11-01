# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703588");
  script_cve_id("CVE-2016-1902", "CVE-2016-4423");
  script_tag(name:"creation_date", value:"2016-05-28 22:00:00 +0000 (Sat, 28 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-03 14:50:00 +0000 (Fri, 03 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3588)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3588");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3588");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-3588 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Symfony, a PHP framework.

CVE-2016-1902

Lander Brandt discovered that the class SecureRandom might generate weak random numbers for cryptographic use under certain settings. If the functions random_bytes() or openssl_random_pseudo_bytes() are not available, the output of SecureRandom should not be consider secure.

CVE-2016-4423

Marek Alaksa from Citadelo discovered that it is possible to fill up the session storage space by submitting inexistent large usernames.

For the stable distribution (jessie), these problems have been fixed in version 2.3.21+dfsg-4+deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 2.8.6+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 2.8.6+dfsg-1.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
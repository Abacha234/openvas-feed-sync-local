# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704752");
  script_cve_id("CVE-2020-8619", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_tag(name:"creation_date", value:"2020-08-28 03:00:16 +0000 (Fri, 28 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4752)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4752");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4752");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-4752 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BIND, a DNS server implementation.

CVE-2020-8619

It was discovered that an asterisk character in an empty non terminal can cause an assertion failure, resulting in denial of service.

CVE-2020-8622

Dave Feldman, Jeff Warren, and Joel Cunningham reported that a truncated TSIG response can lead to an assertion failure, resulting in denial of service.

CVE-2020-8623

Lyu Chiy reported that a flaw in the native PKCS#11 code can lead to a remotely triggerable assertion failure, resulting in denial of service.

CVE-2020-8624

Joop Boonen reported that update-policy rules of type subdomain are enforced incorrectly, allowing updates to all parts of the zone along with the intended subdomain.

For the stable distribution (buster), these problems have been fixed in version 1:9.11.5.P4+dfsg-5.1+deb10u2.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
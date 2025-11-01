# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703773");
  script_cve_id("CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731");
  script_tag(name:"creation_date", value:"2017-01-26 23:00:00 +0000 (Thu, 26 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:16:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-3773)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3773");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3773");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-3773 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in OpenSSL:

CVE-2016-7056

A local timing attack was discovered against ECDSA P-256.

CVE-2016-8610

It was discovered that no limit was imposed on alert packets during an SSL handshake.

CVE-2017-3731

Robert Swiecki discovered that the RC4-MD5 cipher when running on 32 bit systems could be forced into an out-of-bounds read, resulting in denial of service.

For the stable distribution (jessie), these problems have been fixed in version 1.0.1t-1+deb8u6.

For the unstable distribution (sid), these problems have been fixed in version 1.1.0d-1 of the openssl source package and in version 1.0.2k-1 of the openssl1.0 source package.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
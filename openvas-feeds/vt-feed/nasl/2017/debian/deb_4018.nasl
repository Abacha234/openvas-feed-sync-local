# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704018");
  script_cve_id("CVE-2017-3735");
  script_tag(name:"creation_date", value:"2017-11-03 23:00:00 +0000 (Fri, 03 Nov 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Debian: Security Advisory (DSA-4018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4018");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4018");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170828.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171102.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-4018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-3735

It was discovered that OpenSSL is prone to a one-byte buffer overread while parsing a malformed IPAddressFamily extension in an X.509 certificate.

Details can be found in the upstream advisory: [link moved to references]

CVE-2017-3736

It was discovered that OpenSSL contains a carry propagation bug in the x86_64 Montgomery squaring procedure.

Details can be found in the upstream advisory: [link moved to references]

For the oldstable distribution (jessie), CVE-2017-3735 has been fixed in version 1.0.1t-1+deb8u7. The oldstable distribution is not affected by CVE-2017-3736.

For the stable distribution (stretch), these problems have been fixed in version 1.1.0f-3+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 1.1.0g-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704065");
  script_cve_id("CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"creation_date", value:"2017-12-16 23:00:00 +0000 (Sat, 16 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 11:49:00 +0000 (Fri, 19 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-4065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4065");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4065");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl1.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl1.0' package(s) announced via the DSA-4065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in OpenSSL, a Secure Sockets Layer toolkit. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-3737

David Benjamin of Google reported that OpenSSL does not properly handle SSL_read() and SSL_write() while being invoked in an error state, causing data to be passed without being decrypted or encrypted directly from the SSL/TLS record layer.

CVE-2017-3738

It was discovered that OpenSSL contains an overflow bug in the AVX2 Montgomery multiplication procedure used in exponentiation with 1024-bit moduli.

Details can be found in the upstream advisory: [link moved to references]

For the stable distribution (stretch), these problems have been fixed in version 1.0.2l-2+deb9u2.

We recommend that you upgrade your openssl1.0 packages.

For the detailed security status of openssl1.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssl1.0' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
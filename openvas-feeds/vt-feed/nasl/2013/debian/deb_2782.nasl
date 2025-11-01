# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702782");
  script_cve_id("CVE-2013-4623", "CVE-2013-5914", "CVE-2013-5915");
  script_tag(name:"creation_date", value:"2013-10-19 22:00:00 +0000 (Sat, 19 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2782)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2782");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2782");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'polarssl' package(s) announced via the DSA-2782 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in PolarSSL, a lightweight crypto and SSL/TLS library:

CVE-2013-4623

Jack Lloyd discovered a denial of service vulnerability in the parsing of PEM-encoded certificates.

CVE-2013-5914

Paul Brodeur and TrustInSoft discovered a buffer overflow in the ssl_read_record() function, allowing the potential execution of arbitrary code.

CVE-2013-5915

Cyril Arnaud and Pierre-Alain Fouque discovered timing attacks against the RSA implementation.

For the oldstable distribution (squeeze), these problems will be fixed in version 1.2.9-1~deb6u1 soon (due to a technical limitation the updates cannot be released synchronously).

For the stable distribution (wheezy), these problems have been fixed in version 1.2.9-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.3.1-1.

We recommend that you upgrade your polarssl packages.");

  script_tag(name:"affected", value:"'polarssl' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
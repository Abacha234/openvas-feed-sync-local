# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704305");
  script_cve_id("CVE-2018-16151", "CVE-2018-16152");
  script_tag(name:"creation_date", value:"2018-09-23 22:00:00 +0000 (Sun, 23 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-01 01:15:00 +0000 (Sun, 01 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-4305)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4305");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4305");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/strongswan");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-4305 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sze Yiu Chau and his team from Purdue University and The University of Iowa found several issues in the gmp plugin for strongSwan, an IKE/IPsec suite.

Problems in the parsing and verification of RSA signatures could lead to a Bleichenbacher-style low-exponent signature forgery in certificates and during IKE authentication.

While the gmp plugin doesn't allow arbitrary data after the ASN.1 structure (the original Bleichenbacher attack), the ASN.1 parser is not strict enough and allows data in specific fields inside the ASN.1 structure.

Only installations using the gmp plugin are affected (on Debian OpenSSL plugin has priority over GMP one for RSA operations), and only when using keys and certificates (including ones from CAs) using keys with an exponent e = 3, which is usually rare in practice.

CVE-2018-16151

The OID parser in the ASN.1 code in gmp allows any number of random bytes after a valid OID.

CVE-2018-16152

The algorithmIdentifier parser in the ASN.1 code in gmp doesn't enforce a NULL value for the optional parameter which is not used with any PKCS#1 algorithm.

For the stable distribution (stretch), these problems have been fixed in version 5.5.1-4+deb9u3.

We recommend that you upgrade your strongswan packages.

For the detailed security status of strongswan please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
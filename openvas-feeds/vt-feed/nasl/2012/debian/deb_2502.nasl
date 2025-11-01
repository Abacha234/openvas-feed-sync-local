# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71480");
  script_cve_id("CVE-2012-2417");
  script_tag(name:"creation_date", value:"2012-08-10 07:07:10 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2502)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2502");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2502");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-crypto' package(s) announced via the DSA-2502 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ElGamal code in PythonCrypto, a collection of cryptographic algorithms and protocols for Python used insecure insufficient prime numbers in key generation, which lead to a weakened signature or public key space, allowing easier brute force attacks on such keys.

For the stable distribution (squeeze), this problem has been fixed in version 2.1.0-2+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 2.6-1.

We recommend that you upgrade your python-crypto packages. After installing this update, previously generated keys need to be regenerated.");

  script_tag(name:"affected", value:"'python-crypto' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
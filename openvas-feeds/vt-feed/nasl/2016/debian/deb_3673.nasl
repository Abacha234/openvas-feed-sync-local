# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703673");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_tag(name:"creation_date", value:"2016-09-21 22:00:00 +0000 (Wed, 21 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");

  script_name("Debian: Security Advisory (DSA-3673)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3673");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3673");
  script_xref(name:"URL", value:"https://www.openssl.org/blog/blog/2016/06/27/undefined-pointer-arithmetic/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-3673 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in OpenSSL:

CVE-2016-2177

Guido Vranken discovered that OpenSSL uses undefined pointer arithmetic. Additional information can be found at [link moved to references]

CVE-2016-2178

Cesar Pereida, Billy Brumley and Yuval Yarom discovered a timing leak in the DSA code.

CVE-2016-2179 / CVE-2016-2181 Quan Luo and the OCAP audit team discovered denial of service vulnerabilities in DTLS.

CVE-2016-2180 / CVE-2016-2182 / CVE-2016-6303 Shi Lei discovered an out-of-bounds memory read in TS_OBJ_print_bio() and an out-of-bounds write in BN_bn2dec() and MDC2_Update().

CVE-2016-2183

DES-based cipher suites are demoted from the HIGH group to MEDIUM as a mitigation for the SWEET32 attack.

CVE-2016-6302

Shi Lei discovered that the use of SHA512 in TLS session tickets is susceptible to denial of service.

CVE-2016-6304

Shi Lei discovered that excessively large OCSP status request may result in denial of service via memory exhaustion.

CVE-2016-6306

Shi Lei discovered that missing message length validation when parsing certificates may potentially result in denial of service.

For the stable distribution (jessie), these problems have been fixed in version 1.0.1t-1+deb8u4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702833");
  script_cve_id("CVE-2013-6449", "CVE-2013-6450");
  script_tag(name:"creation_date", value:"2013-12-31 23:00:00 +0000 (Tue, 31 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2833)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2833");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2833");
  script_xref(name:"URL", value:"http://marc.info/?l=openssl-announce&m=138747119822324&w=2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2833 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been fixed in OpenSSL: The TLS 1.2 support was susceptible to denial of service and retransmission of DTLS messages was fixed. In addition this update disables the insecure Dual_EC_DRBG algorithm (which was unused anyway, see [link moved to references] for further information) and no longer uses the RdRand feature available on some Intel CPUs as a sole source of entropy unless explicitly requested.

For the stable distribution (wheezy), these problems have been fixed in version 1.0.1e-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.0.1e-5.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
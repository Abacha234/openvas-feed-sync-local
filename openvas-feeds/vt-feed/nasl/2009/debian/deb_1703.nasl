# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63150");
  script_cve_id("CVE-2009-0025");
  script_tag(name:"creation_date", value:"2009-01-13 21:38:32 +0000 (Tue, 13 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1703)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1703");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1703");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-1703 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BIND, an implementation of the DNS protocol suite, does not properly check the result of an OpenSSL function which is used to verify DSA cryptographic signatures. As a result, incorrect DNS resource records in zones protected by DNSSEC could be accepted as genuine.

For the stable distribution (etch), this problem has been fixed in version 9.3.4-2etch4.

For the unstable distribution (sid) and the testing distribution (lenny), this problem will be fixed soon.

We recommend that you upgrade your BIND packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
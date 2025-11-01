# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702626");
  script_cve_id("CVE-2009-3555", "CVE-2012-4929");
  script_tag(name:"creation_date", value:"2013-02-16 23:00:00 +0000 (Sat, 16 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2626)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2626");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2626");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lighttpd' package(s) announced via the DSA-2626 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the TLS/SSL protocol. This update addresses these protocol vulnerabilities in lighttpd.

CVE-2009-3555

Marsh Ray, Steve Dispensa, and Martin Rex discovered that the TLS and SSLv3 protocols do not properly associate renegotiation handshakes with an existing connection, which allows man-in-the-middle attackers to insert data into HTTPS sessions. This issue is solved in lighttpd by disabling client initiated renegotiation by default.

Those users that do actually need such renegotiations, can re-enable them via the new ssl.disable-client-renegotiation parameter.

CVE-2012-4929

Juliano Rizzo and Thai Duong discovered a weakness in the TLS/SSL protocol when using compression. This side channel attack, dubbed CRIME, allows eavesdroppers to gather information to recover the original plaintext in the protocol. This update disables compression.

For the stable distribution (squeeze), these problems have been fixed in version 1.4.28-2+squeeze1.2.

For the testing distribution (wheezy), and the unstable distribution (sid) these problems have been fixed in version 1.4.30-1.

We recommend that you upgrade your lighttpd packages.");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
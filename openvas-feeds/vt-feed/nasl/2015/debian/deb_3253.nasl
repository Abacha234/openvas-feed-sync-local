# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703253");
  script_cve_id("CVE-2009-3555", "CVE-2012-4929", "CVE-2014-3566");
  script_tag(name:"creation_date", value:"2015-05-06 22:00:00 +0000 (Wed, 06 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-3253)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3253");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3253");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pound' package(s) announced via the DSA-3253 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pound, a HTTP reverse proxy and load balancer, had several issues related to vulnerabilities in the Secure Sockets Layer (SSL) protocol.

For Debian 7 (wheezy) this update adds a missing part to make it actually possible to disable client-initiated renegotiation and disables it by default (CVE-2009-3555). TLS compression is disabled (CVE-2012-4929), although this is normally already disabled by the OpenSSL system library. Finally it adds the ability to disable the SSLv3 protocol (CVE-2014-3566) entirely via the new DisableSSLv3 configuration directive, although it will not disabled by default in this update. Additionally a non-security sensitive issue in redirect encoding is addressed.

For Debian 8 (jessie) these issues have been fixed prior to the release, with the exception of client-initiated renegotiation (CVE-2009-3555). This update addresses that issue for jessie.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.6-2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 2.6-6+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 2.6-6.1.

We recommend that you upgrade your pound packages.");

  script_tag(name:"affected", value:"'pound' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64775");
  script_cve_id("CVE-2008-4989", "CVE-2009-2409", "CVE-2009-2730");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-809-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-809-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-809-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/305264");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls12, gnutls13, gnutls26' package(s) announced via the USN-809-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moxie Marlinspike and Dan Kaminsky independently discovered that GnuTLS did
not properly handle certificates with NULL characters in the certificate
name. An attacker could exploit this to perform a machine-in-the-middle attack
to view sensitive information or alter encrypted communications.
(CVE-2009-2730)

Dan Kaminsky discovered GnuTLS would still accept certificates with MD2
hash signatures. As a result, an attacker could potentially create a
malicious trusted certificate to impersonate another site. This issue only
affected Ubuntu 6.06 LTS and Ubuntu 8.10. (CVE-2009-2409)

USN-678-1 fixed a vulnerability and USN-678-2 a regression in GnuTLS. The
 upstream patches introduced a regression when validating certain certificate
 chains that would report valid certificates as untrusted. This update
 fixes the problem, and only affected Ubuntu 6.06 LTS and Ubuntu 8.10 (Ubuntu
 8.04 LTS and 9.04 were fixed at an earlier date). In an effort to maintain a
 strong security stance and address all known regressions, this update
 deprecates X.509 validation chains using MD2 and MD5 signatures. To accommodate
 sites which must still use a deprecated RSA-MD5 certificate, GnuTLS has been
 updated to stop looking when it has found a trusted intermediary certificate.
 This new handling of intermediary certificates is in accordance with other SSL
 implementations.

Original advisory details:

 Martin von Gagern discovered that GnuTLS did not properly verify
 certificate chains when the last certificate in the chain was self-signed.
 If a remote attacker were able to perform a machine-in-the-middle attack, this
 flaw could be exploited to view sensitive information. (CVE-2008-4989)");

  script_tag(name:"affected", value:"'gnutls12, gnutls13, gnutls26' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

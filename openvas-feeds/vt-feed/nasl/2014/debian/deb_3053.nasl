# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703053");
  script_cve_id("CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3568");
  script_tag(name:"creation_date", value:"2014-10-15 22:00:00 +0000 (Wed, 15 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3053)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3053");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3053");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-3053 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in OpenSSL, the Secure Sockets Layer library and toolkit.

CVE-2014-3513

A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure Real-time Transport Protocol (SRTP) extension data. A remote attacker could send multiple specially crafted handshake messages to exhaust all available memory of an SSL/TLS or DTLS server.

CVE-2014-3566 ('POODLE')

A flaw was found in the way SSL 3.0 handled padding bytes when decrypting messages encrypted using block ciphers in cipher block chaining (CBC) mode. This flaw allows a man-in-the-middle (MITM) attacker to decrypt a selected byte of a cipher text in as few as 256 tries if they are able to force a victim application to repeatedly send the same data over newly created SSL 3.0 connections.

This update adds support for Fallback SCSV to mitigate this issue.

CVE-2014-3567

A memory leak flaw was found in the way an OpenSSL handled failed session ticket integrity checks. A remote attacker could exhaust all available memory of an SSL/TLS or DTLS server by sending a large number of invalid session tickets to that server.

CVE-2014-3568

When OpenSSL is configured with 'no-ssl3' as a build option, servers could accept and complete a SSL 3.0 handshake, and clients could be configured to send them.

For the stable distribution (wheezy), these problems have been fixed in version 1.0.1e-2+deb7u13.

For the unstable distribution (sid), these problems have been fixed in version 1.0.1j-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
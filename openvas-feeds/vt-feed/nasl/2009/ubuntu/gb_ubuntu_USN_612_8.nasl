# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840281");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-612-8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-612-8");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-612-8");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-blacklist' package(s) announced via the USN-612-8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-612-3 addressed a weakness in OpenSSL certificate and key
generation in OpenVPN by introducing openssl-blacklist to aid in
detecting vulnerable private keys. This update enhances the
openssl-vulnkey tool to check X.509 certificates as well, and
provides the corresponding update for Ubuntu 6.06. While the
OpenSSL in Ubuntu 6.06 was not vulnerable, openssl-blacklist is
now provided for Ubuntu 6.06 for checking certificates and keys
that may have been imported on these systems.

This update also includes the complete RSA-1024 and RSA-2048
blocklists for all Ubuntu architectures, as well as support for
other future blocklists for non-standard bit lengths.

You can check for weak SSL/TLS certificates by installing
openssl-blacklist via your package manager, and using the
openssl-vulnkey command.

$ openssl-vulnkey /path/to/certificate_or_key

This command can be used on public certificates and private keys
for any X.509 certificate or RSA key, including ones for web
servers, mail servers, OpenVPN, and others. If in doubt, destroy
the certificate and key and generate new ones. Please consult the
documentation for your software when recreating SSL/TLS
certificates. Also, if certificates have been generated for use
on other systems, they must be found and replaced as well.

Original advisory details:

 A weakness has been discovered in the random number generator used
 by OpenSSL on Debian and Ubuntu systems. As a result of this
 weakness, certain encryption keys are much more common than they
 should be, such that an attacker could guess the key through a
 brute-force attack given minimal knowledge of the system. This
 particularly affects the use of encryption keys in OpenSSH, OpenVPN
 and SSL certificates.");

  script_tag(name:"affected", value:"'openssl-blacklist' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

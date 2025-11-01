# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840338");
  script_cve_id("CVE-2008-0166");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-612-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-612-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-612-4");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-612-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ssl-cert' package(s) announced via the USN-612-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-612-1 fixed vulnerabilities in openssl. This update provides the
corresponding updates for ssl-cert -- potentially compromised snake-oil
SSL certificates will be regenerated.

Original advisory details:

 A weakness has been discovered in the random number generator used
 by OpenSSL on Debian and Ubuntu systems. As a result of this
 weakness, certain encryption keys are much more common than they
 should be, such that an attacker could guess the key through a
 brute-force attack given minimal knowledge of the system. This
 particularly affects the use of encryption keys in OpenSSH, OpenVPN
 and SSL certificates.

 This vulnerability only affects operating systems which (like
 Ubuntu) are based on Debian. However, other systems can be
 indirectly affected if weak keys are imported into them.

 We consider this an extremely serious vulnerability, and urge all
 users to act immediately to secure their systems. (CVE-2008-0166)

 == Who is affected ==

 Systems which are running any of the following releases:

 * Ubuntu 7.04 (Feisty)
 * Ubuntu 7.10 (Gutsy)
 * Ubuntu 8.04 LTS (Hardy)
 * Ubuntu 'Intrepid Ibex' (development): libssl <= 0.9.8g-8
 * Debian 4.0 (etch) (see corresponding Debian security advisory)

 and have openssh-server installed or have been used to create an
 OpenSSH key or X.509 (SSL) certificate.

 All OpenSSH and X.509 keys generated on such systems must be
 considered untrustworthy, regardless of the system on which they
 are used, even after the update has been applied.

 This includes the automatically generated host keys used by OpenSSH,
 which are the basis for its server spoofing and machine-in-the-middle
 protection.");

  script_tag(name:"affected", value:"'ssl-cert' package(s) on Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

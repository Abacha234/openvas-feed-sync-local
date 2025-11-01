# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53162");
  script_cve_id("CVE-2004-0079", "CVE-2004-0081");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-465");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-465");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl, openssl094, openssl095' package(s) announced via the DSA-465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in openssl, an implementation of the SSL protocol, using the Codenomicon TLS Test Tool. More information can be found in the following NISCC Vulnerability Advisory and this OpenSSL advisory. The Common Vulnerabilities and Exposures project identified the following vulnerabilities:

CAN-2004-0079

Null-pointer assignment in the do_change_cipher_spec() function. A remote attacker could perform a carefully crafted SSL/TLS handshake against a server that used the OpenSSL library in such a way as to cause OpenSSL to crash. Depending on the application this could lead to a denial of service.

CAN-2004-0081

A bug in older versions of OpenSSL 0.9.6 that can lead to a Denial of Service attack (infinite loop).

For the stable distribution (woody) these problems have been fixed in openssl version 0.9.6c-2.woody.6, openssl094 version 0.9.4-6.woody.4 and openssl095 version 0.9.5a-6.woody.5.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your openssl package.");

  script_tag(name:"affected", value:"'openssl, openssl094, openssl095' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
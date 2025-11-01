# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71495");
  script_cve_id("CVE-2012-1014", "CVE-2012-1015");
  script_tag(name:"creation_date", value:"2012-08-10 07:15:01 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2518");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2518");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-2518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanuel Bouillon from NCI Agency discovered multiple vulnerabilities in MIT Kerberos, a daemon implementing the network authentication protocol.

CVE-2012-1014

By sending specially crafted AS-REQ (Authentication Service Request) to a KDC (Key Distribution Center), an attacker could make it free an uninitialized pointer, corrupting the heap. This can lead to process crash or even arbitrary code execution.

This CVE only affects testing (wheezy) and unstable (sid) distributions.

CVE-2012-1015

By sending specially crafted AS-REQ to a KDC, an attacker could make it dereference an uninitialized pointer, leading to process crash or even arbitrary code execution

In both cases, arbitrary code execution is believed to be difficult to achieve, but might not be impossible.

For the stable distribution (squeeze), this problem has been fixed in version 1.8.3+dfsg-4squeeze6.

For the testing distribution (wheezy), this problem has been fixed in version 1.10.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in version 1.10.1+dfsg-2.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
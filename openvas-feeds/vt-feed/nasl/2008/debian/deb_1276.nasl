# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58328");
  script_cve_id("CVE-2007-0956", "CVE-2007-0957", "CVE-2007-1216");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1276)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1276");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1276");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-1276 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the MIT reference implementation of the Kerberos network authentication protocol suite, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-0956

It was discovered that the krb5 telnet daemon performs insufficient validation of usernames, which might allow unauthorized logins or privilege escalation.

CVE-2007-0957

iDefense discovered that a buffer overflow in the logging code of the KDC and the administration daemon might lead to arbitrary code execution.

CVE-2007-1216

It was discovered that a double free in the RPCSEC_GSS part of the GSS library code might lead to arbitrary code execution.

For the stable distribution (sarge) these problems have been fixed in version 1.3.6-2sarge4.

For the upcoming stable distribution (etch) these problems have been fixed in version 1.4.4-7etch1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your Kerberos packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
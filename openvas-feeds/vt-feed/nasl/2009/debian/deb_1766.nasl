# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63793");
  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1766)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1766");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1766");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-1766 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the MIT reference implementation of Kerberos V5, a system for authenticating users and services on a network. The Common Vulnerabilities and Exposures project identified the following problems:

CVE-2009-0844

The Apple Product Security team discovered that the SPNEGO GSS-API mechanism suffers of a missing bounds check when reading a network input buffer which results in an invalid read crashing the application or possibly leaking information.

CVE-2009-0845

Under certain conditions the SPNEGO GSS-API mechanism references a null pointer which crashes the application using the library.

CVE-2009-0847

An incorrect length check inside the ASN.1 decoder of the MIT krb5 implementation allows an unauthenticated remote attacker to crash of the kinit or KDC program.

CVE-2009-0846

Under certain conditions the ASN.1 decoder of the MIT krb5 implementation frees an uninitialized pointer which could lead to denial of service and possibly arbitrary code execution.

For the oldstable distribution (etch), this problem has been fixed in version 1.4.4-7etch7.

For the stable distribution (lenny), this problem has been fixed in version 1.6.dfsg.4~beta1-5lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.6.dfsg.4~beta1-13.

We recommend that you upgrade your krb5 packages.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
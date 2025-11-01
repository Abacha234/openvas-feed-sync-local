# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702710");
  script_cve_id("CVE-2013-2153", "CVE-2013-2154", "CVE-2013-2155", "CVE-2013-2156");
  script_tag(name:"creation_date", value:"2013-06-17 22:00:00 +0000 (Mon, 17 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2710)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2710");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2710");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xml-security-c' package(s) announced via the DSA-2710 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Forshaw from Context Information Security discovered several vulnerabilities in xml-security-c, an implementation of the XML Digital Security specification. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-2153

The implementation of XML digital signatures in the Santuario-C++ library is vulnerable to a spoofing issue allowing an attacker to reuse existing signatures with arbitrary content.

CVE-2013-2154

A stack overflow, possibly leading to arbitrary code execution, exists in the processing of malformed XPointer expressions in the XML Signature Reference processing code.

CVE-2013-2155

A bug in the processing of the output length of an HMAC-based XML Signature would cause a denial of service when processing specially chosen input.

CVE-2013-2156

A heap overflow exists in the processing of the PrefixList attribute optionally used in conjunction with Exclusive Canonicalization, potentially allowing arbitrary code execution.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.5.1-3+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 1.6.1-5+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 1.6.1-6.

We recommend that you upgrade your xml-security-c packages.");

  script_tag(name:"affected", value:"'xml-security-c' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
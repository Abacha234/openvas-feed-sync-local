# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60660");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_tag(name:"creation_date", value:"2008-04-07 18:38:54 +0000 (Mon, 07 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1537)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1537");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1537");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xpdf' package(s) announced via the DSA-1537 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop (Secunia) discovered a number of vulnerabilities in xpdf, a set of tools for display and conversion of Portable Document Format (PDF) files. The Common Vulnerabilities and Exposures project identifies the following three problems:

CVE-2007-4352

Inadequate DCT stream validation allows an attacker to corrupt memory and potentially execute arbitrary code by supplying a maliciously crafted PDF file.

CVE-2007-5392

An integer overflow vulnerability in DCT stream handling could allow an attacker to overflow a heap buffer, enabling the execution of arbitrary code.

CVE-2007-5393

A buffer overflow vulnerability in xpdf's CCITT image compression handlers allows overflow on the heap, allowing an attacker to execute arbitrary code by supplying a maliciously crafted CCITTFaxDecode filter.

For the stable distribution (etch), these problems have been fixed in version 3.01-9.1+etch2.

For the unstable distribution (sid), these problems have been fixed in version 3.02-1.3.

We recommend that you upgrade your xpdf packages.");

  script_tag(name:"affected", value:"'xpdf' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66594");
  script_cve_id("CVE-2009-3979", "CVE-2009-3981", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_tag(name:"creation_date", value:"2009-12-30 20:58:43 +0000 (Wed, 30 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1956)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1956");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1956");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1956 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications, such as the Iceweasel web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-3986: David James discovered that the window.opener property allows Chrome privilege escalation.

CVE-2009-3985: Jordi Chanel discovered a spoofing vulnerability of the URL location bar using the document.location property.

CVE-2009-3984: Jonathan Morgan discovered that the icon indicating a secure connection could be spoofed through the document.location property.

CVE-2009-3983: Takehiro Takahashi discovered that the NTLM implementation is vulnerable to reflection attacks.

CVE-2009-3981: Jesse Ruderman discovered a crash in the layout engine, which might allow the execution of arbitrary code.

CVE-2009-3979: Jesse Ruderman, Josh Soref, Martijn Wargers, Jose Angel and Olli Pettay discovered crashes in the layout engine, which might allow the execution of arbitrary code.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.16-1.

For the unstable distribution (sid), these problems have been fixed in version 1.9.1.6-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
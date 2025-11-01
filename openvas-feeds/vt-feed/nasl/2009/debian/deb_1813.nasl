# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64186");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_tag(name:"creation_date", value:"2009-06-09 17:38:29 +0000 (Tue, 09 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1813)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1813");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1813");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evolution-data-server' package(s) announced via the DSA-1813 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in evolution-data-server, the database backend server for the evolution groupware suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0587

It was discovered that evolution-data-server is prone to integer overflows triggered by large base64 strings.

CVE-2009-0547

Joachim Breitner discovered that S/MIME signatures are not verified properly, which can lead to spoofing attacks.

CVE-2009-0582

It was discovered that NTLM authentication challenge packets are not validated properly when using the NTLM authentication method, which could lead to an information disclosure or a denial of service.

For the oldstable distribution (etch), these problems have been fixed in version 1.6.3-5etch2.

For the stable distribution (lenny), these problems have been fixed in version 2.22.3-1.1+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 2.26.1.1-1.

We recommend that you upgrade your evolution-data-server packages.");

  script_tag(name:"affected", value:"'evolution-data-server' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
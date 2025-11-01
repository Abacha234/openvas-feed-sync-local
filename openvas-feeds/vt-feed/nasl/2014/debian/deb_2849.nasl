# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702849");
  script_cve_id("CVE-2014-0015");
  script_tag(name:"creation_date", value:"2014-01-30 23:00:00 +0000 (Thu, 30 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2849");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2849");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-2849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paras Sethia discovered that libcurl, a client-side URL transfer library, would sometimes mix up multiple HTTP and HTTPS connections with NTLM authentication to the same server, sending requests for one user over the connection authenticated as a different user.

For the oldstable distribution (squeeze), this problem has been fixed in version 7.21.0-2.1+squeeze7.

For the stable distribution (wheezy), this problem has been fixed in version 7.26.0-1+wheezy8.

For the unstable distribution (sid), this problem has been fixed in version 7.35.0-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
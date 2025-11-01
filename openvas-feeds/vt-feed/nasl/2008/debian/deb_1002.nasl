# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56410");
  script_cve_id("CVE-2005-3949", "CVE-2005-3961", "CVE-2005-3982", "CVE-2005-3984");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1002");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1002");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'webcalendar' package(s) announced via the DSA-1002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in webcalendar, a PHP based multi-user calendar. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2005-3949

Multiple SQL injection vulnerabilities allow remote attackers to execute arbitrary SQL commands.

CVE-2005-3961

Missing input sanitising allows an attacker to overwrite local files.

CVE-2005-3982

A CRLF injection vulnerability allows remote attackers to modify HTTP headers and conduct HTTP response splitting attacks.

The old stable distribution (woody) does not contain webcalendar packages.

For the stable distribution (sarge) these problems have been fixed in version 0.9.45-4sarge3.

For the unstable distribution (sid) these problems have been fixed in version 1.0.2-1.

We recommend that you upgrade your webcalendar package.");

  script_tag(name:"affected", value:"'webcalendar' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
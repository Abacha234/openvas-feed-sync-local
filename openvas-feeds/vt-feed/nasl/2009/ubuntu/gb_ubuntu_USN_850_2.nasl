# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66113");
  script_cve_id("CVE-2009-3605");
  script_tag(name:"creation_date", value:"2009-10-27 00:37:56 +0000 (Tue, 27 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-850-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-850-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-850-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/457985");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-850-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-850-1 fixed vulnerabilities in poppler. The security fix for
CVE-2009-3605 introduced a regression that would cause certain
applications, such as Okular, to segfault when opening certain PDF files.

This update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 It was discovered that poppler contained multiple security issues when
 parsing malformed PDF documents. If a user or automated system were tricked
 into opening a crafted PDF file, an attacker could cause a denial of
 service or execute arbitrary code with privileges of the user invoking the
 program.");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

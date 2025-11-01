# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840117");
  script_cve_id("CVE-2007-2444");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-460-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-460-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-460-2");
  script_xref(name:"URL", value:"http://bugs.debian.org/424629");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the USN-460-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-460-1 fixed several vulnerabilities in Samba. The upstream changes
for CVE-2007-2444 had an unexpected side-effect in Feisty. Shares
configured with the 'force group' option no longer behaved correctly.
This update corrects the problem. We apologize for the inconvenience.

Original advisory details:

 Paul Griffith and Andrew Hogue discovered that Samba did not fully drop
 root privileges while translating SIDs. A remote authenticated user
 could issue SMB operations during a small window of opportunity and gain
 root privileges. (CVE-2007-2444)");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

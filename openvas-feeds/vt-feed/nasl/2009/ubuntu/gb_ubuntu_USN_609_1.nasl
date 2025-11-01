# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840305");
  script_cve_id("CVE-2007-4575", "CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-609-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-609-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-609-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hsqldb, openoffice.org, openoffice.org-amd64' package(s) announced via the USN-609-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that arbitrary Java methods were not filtered out when
opening databases in OpenOffice.org. If a user were tricked into running
a specially crafted query, a remote attacker could execute arbitrary
Java with user privileges. (CVE-2007-4575)

Multiple memory overflow flaws were discovered in OpenOffice.org's
handling of Quattro Pro, EMF, and OLE files. If a user were tricked
into opening a specially crafted document, a remote attacker might be
able to execute arbitrary code with user privileges. (CVE-2007-5745,
CVE-2007-5746, CVE-2007-5747, CVE-2008-0320)");

  script_tag(name:"affected", value:"'hsqldb, openoffice.org, openoffice.org-amd64' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

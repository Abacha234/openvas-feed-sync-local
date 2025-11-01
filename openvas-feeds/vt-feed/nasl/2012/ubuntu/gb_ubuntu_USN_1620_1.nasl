# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841200");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_tag(name:"creation_date", value:"2012-10-29 05:33:49 +0000 (Mon, 29 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1620-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1620-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1620-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1620-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mariusz Mlynski and others discovered several flaws in Firefox that allowed
a remote attacker to conduct cross-site scripting (XSS) attacks.
(CVE-2012-4194, CVE-2012-4195)

Antoine Delignat-Lavaud discovered a flaw in the way Firefox handled the
Location object. If a user were tricked into opening a specially crafted
page, a remote attacker could exploit this to bypass security protections
and perform cross-origin reading of the Location object. (CVE-2012-4196)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

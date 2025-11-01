# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842670");
  script_cve_id("CVE-2016-2512", "CVE-2016-2513");
  script_tag(name:"creation_date", value:"2016-03-02 05:17:54 +0000 (Wed, 02 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");

  script_name("Ubuntu: Security Advisory (USN-2915-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2915-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2915-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2915-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mark Striemer discovered that Django incorrectly handled user-supplied
redirect URLs containing basic authentication credentials. A remote
attacker could possibly use this issue to perform a cross-site scripting
attack or a malicious redirect. (CVE-2016-2512)

Sjoerd Job Postmus discovered that Django incorrectly handled timing when
doing password hashing operations. A remote attacker could possibly use
this issue to perform user enumeration. (CVE-2016-2513)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

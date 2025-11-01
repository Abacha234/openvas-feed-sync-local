# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841687");
  script_cve_id("CVE-2014-0978", "CVE-2014-1235", "CVE-2014-1236");
  script_tag(name:"creation_date", value:"2014-01-20 04:37:40 +0000 (Mon, 20 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 01:34:00 +0000 (Tue, 29 Aug 2017)");

  script_name("Ubuntu: Security Advisory (USN-2083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2083-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2083-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz' package(s) announced via the USN-2083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Graphviz incorrectly handled memory in the yyerror
function. If a user were tricked into opening a specially crafted dot file,
an attacker could cause Graphviz to crash, or possibly execute arbitrary
code. (CVE-2014-0978, CVE-2014-1235)

It was discovered that Graphviz incorrectly handled memory in the chkNum
function. If a user were tricked into opening a specially crafted dot file,
an attacker could cause Graphviz to crash, or possibly execute arbitrary
code. (CVE-2014-1236)

The default compiler options for affected releases should reduce the
vulnerability to a denial of service.");

  script_tag(name:"affected", value:"'graphviz' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

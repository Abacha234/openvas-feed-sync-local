# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841638");
  script_cve_id("CVE-2013-2065", "CVE-2013-4164");
  script_tag(name:"creation_date", value:"2013-12-03 09:18:35 +0000 (Tue, 03 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2035-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2035-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.8, ruby1.9.1' package(s) announced via the USN-2035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Charlie Somerville discovered that Ruby incorrectly handled floating point
number conversion. An attacker could possibly use this issue with an
application that converts text to floating point numbers to cause the
application to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2013-4164)

Vit Ondruch discovered that Ruby did not perform taint checking for certain
functions. An attacker could possibly use this issue to bypass certain
intended restrictions. (CVE-2013-2065)");

  script_tag(name:"affected", value:"'ruby1.8, ruby1.9.1' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

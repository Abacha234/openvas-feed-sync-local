# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841136");
  script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
  script_tag(name:"creation_date", value:"2012-09-11 04:08:22 +0000 (Tue, 11 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1560-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1560-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1560-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-1560-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Django incorrectly validated the scheme of a
redirect target. If a user were tricked into opening a specially crafted
URL, an attacker could possibly exploit this to conduct cross-site
scripting (XSS) attacks. (CVE-2012-3442)

It was discovered that Django incorrectly handled validating certain
images. A remote attacker could use this flaw to cause the server to
consume memory, leading to a denial of service. (CVE-2012-3443)

Jeroen Dekkers discovered that Django incorrectly handled certain image
dimensions. A remote attacker could use this flaw to cause the server to
consume resources, leading to a denial of service. (CVE-2012-3444)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

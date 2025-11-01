# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841571");
  script_cve_id("CVE-2013-2099", "CVE-2013-4238");
  script_tag(name:"creation_date", value:"2013-10-03 04:50:18 +0000 (Thu, 03 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1984-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1984-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.2' package(s) announced via the USN-1984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that Python incorrectly handled matching multiple
wildcards in ssl certificate hostnames. An attacker could exploit this to
cause Python to consume resources, resulting in a denial of service.
(CVE-2013-2099)

Ryan Sleevi discovered that Python did not properly handle certificates
with NULL characters in the Subject Alternative Name field. An attacker
could exploit this to perform a machine-in-the-middle attack to view sensitive
information or alter encrypted communications. (CVE-2013-4238)");

  script_tag(name:"affected", value:"'python3.2' package(s) on Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

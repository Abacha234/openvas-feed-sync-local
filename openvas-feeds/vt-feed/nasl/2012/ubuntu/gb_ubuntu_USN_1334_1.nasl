# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840868");
  script_cve_id("CVE-2011-0216", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919");
  script_tag(name:"creation_date", value:"2012-01-20 05:30:26 +0000 (Fri, 20 Jan 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1334-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1334-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-1334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libxml2 contained an off by one error. If a user or
application linked against libxml2 were tricked into opening a specially
crafted XML file, an attacker could cause the application to crash or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2011-0216)

It was discovered that libxml2 is vulnerable to double-free conditions
when parsing certain XML documents. This could allow a remote attacker to
cause a denial of service. (CVE-2011-2821, CVE-2011-2834)

It was discovered that libxml2 did not properly detect end of file when
parsing certain XML documents. An attacker could exploit this to crash
applications linked against libxml2. (CVE-2011-3905)

It was discovered that libxml2 did not properly decode entity references
with long names. If a user or application linked against libxml2 were
tricked into opening a specially crafted XML file, an attacker could cause
the application to crash or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2011-3919)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

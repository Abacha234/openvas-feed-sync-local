# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842207");
  script_cve_id("CVE-2015-3622");
  script_tag(name:"creation_date", value:"2015-05-12 03:44:01 +0000 (Tue, 12 May 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2604-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2604-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1-3, libtasn1-6' package(s) announced via the USN-2604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that Libtasn1 incorrectly handled certain ASN.1 data.
A remote attacker could possibly exploit this with specially crafted ASN.1
data and cause applications using Libtasn1 to crash, resulting in a denial
of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'libtasn1-3, libtasn1-6' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

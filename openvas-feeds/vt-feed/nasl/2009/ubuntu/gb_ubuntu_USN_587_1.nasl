# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840334");
  script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-587-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-587-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that krb5 did not correctly handle certain krb4
requests. An unauthenticated remote attacker could exploit this flaw
by sending a specially crafted traffic, which could expose sensitive
information, cause a crash, or execute arbitrary code. (CVE-2008-0062,
CVE-2008-0063)

A flaw was discovered in the kadmind service's handling of file
descriptors. An unauthenticated remote attacker could send specially
crafted requests that would cause a crash, resulting in a denial of
service. Only systems with configurations allowing large numbers of
open file descriptors were vulnerable. (CVE-2008-0947)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

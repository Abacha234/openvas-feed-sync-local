# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841662");
  script_cve_id("CVE-2013-6391");
  script_tag(name:"creation_date", value:"2013-12-23 07:54:24 +0000 (Mon, 23 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2061-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2061-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2061-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keystone' package(s) announced via the USN-2061-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steven Hardy discovered that Keystone did not properly enforce trusts when
using the ec2tokens API. An authenticated attacker could exploit this to
retrieve a token not scoped to the trust and elevate privileges to the
trustor's roles.");

  script_tag(name:"affected", value:"'keystone' package(s) on Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

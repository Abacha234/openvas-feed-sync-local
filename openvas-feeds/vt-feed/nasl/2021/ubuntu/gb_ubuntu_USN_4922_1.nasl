# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844905");
  script_cve_id("CVE-2021-28965");
  script_tag(name:"creation_date", value:"2021-04-21 03:00:27 +0000 (Wed, 21 Apr 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 18:37:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4922-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4922-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4922-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.3, ruby2.5, ruby2.7' package(s) announced via the USN-4922-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Juho Nurminen discovered that the REXML gem bundled with Ruby incorrectly
parsed and serialized XML documents. A remote attacker could possibly use
this issue to perform an XML round-trip attack.");

  script_tag(name:"affected", value:"'ruby2.3, ruby2.5, ruby2.7' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

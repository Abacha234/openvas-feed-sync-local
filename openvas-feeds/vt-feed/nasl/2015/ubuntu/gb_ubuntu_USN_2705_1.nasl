# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842402");
  script_cve_id("CVE-2014-7144", "CVE-2015-1852");
  script_tag(name:"creation_date", value:"2015-08-06 05:02:07 +0000 (Thu, 06 Aug 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2705-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2705-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-keystoneclient, python-keystonemiddleware' package(s) announced via the USN-2705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qin Zhao discovered Keystone disabled certification verification when
the 'insecure' option is set in a paste configuration (paste.ini)
file regardless of the value, which allows remote attackers to conduct
machine-in-the-middle attacks via a crafted certificate. (CVE-2014-7144)

Brant Knudson discovered Keystone disabled certification verification when
the 'insecure' option is set in a paste configuration (paste.ini)
file regardless of the value, which allows remote attackers to conduct
machine-in-the-middle attacks via a crafted certificate. (CVE-2015-1852)");

  script_tag(name:"affected", value:"'python-keystoneclient, python-keystonemiddleware' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

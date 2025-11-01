# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841690");
  script_cve_id("CVE-2013-6402", "CVE-2013-6427");
  script_tag(name:"creation_date", value:"2014-01-27 05:52:21 +0000 (Mon, 27 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2085-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2085-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2085-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the USN-2085-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the HPLIP Polkit daemon incorrectly handled
temporary files. A local attacker could possibly use this issue to
overwrite arbitrary files. In the default installation of Ubuntu 12.04 LTS
and higher, this should be prevented by the Yama link restrictions.
(CVE-2013-6402)

It was discovered that HPLIP contained an upgrade tool that would download
code in an unsafe fashion. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could be exploited to execute arbitrary
code. (CVE-2013-6427)");

  script_tag(name:"affected", value:"'hplip' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

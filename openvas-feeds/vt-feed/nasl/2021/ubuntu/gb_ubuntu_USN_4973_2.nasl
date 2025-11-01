# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845091");
  script_cve_id("CVE-2021-29921");
  script_tag(name:"creation_date", value:"2021-10-05 01:00:49 +0000 (Tue, 05 Oct 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-4973-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4973-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4973-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1945240");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.8' package(s) announced via the USN-4973-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4973-1 fixed this vulnerability previously, but it was re-introduced
in python3.8 in focal because of the SRU in LP: #1928057. This update fixes
the problem.

Original advisory details:

 It was discovered that the Python stdlib ipaddress API incorrectly handled
 octal strings. A remote attacker could possibly use this issue to perform a
 wide variety of attacks, including bypassing certain access restrictions.");

  script_tag(name:"affected", value:"'python3.8' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845390");
  script_cve_id("CVE-2019-8842", "CVE-2020-10001", "CVE-2022-26691");
  script_tag(name:"creation_date", value:"2022-06-01 01:00:35 +0000 (Wed, 01 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 02:52:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5454-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5454-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5454-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-5454-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joshua Mason discovered that CUPS incorrectly handled the secret key used
to access the administrative web interface. A remote attacker could
possibly use this issue to open a session as an administrator and execute
arbitrary code. (CVE-2022-26691)

It was discovered that CUPS incorrectly handled certain memory operations
when handling IPP printing. A remote attacker could possibly use this issue
to cause CUPS to crash, leading to a denial of service, or obtain sensitive
information. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04
LTS. (CVE-2019-8842, CVE-2020-10001)");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

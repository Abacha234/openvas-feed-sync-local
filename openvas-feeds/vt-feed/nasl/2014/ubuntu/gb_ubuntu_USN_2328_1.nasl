# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841946");
  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_tag(name:"creation_date", value:"2014-08-29 03:52:18 +0000 (Fri, 29 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2328-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2328-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc' package(s) announced via the USN-2328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy and John Haxby discovered that the GNU C Library contained an
off-by-one error when performing transliteration module loading. A local
attacker could exploit this to gain administrative privileges.
(CVE-2014-5119)

USN-2306-1 fixed vulnerabilities in the GNU C Library. On Ubuntu 10.04 LTS
and Ubuntu 12.04 LTS the security update for CVE-2014-0475 caused a
regression with localplt on PowerPC. This update fixes the problem. We
apologize for the inconvenience.");

  script_tag(name:"affected", value:"'eglibc' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

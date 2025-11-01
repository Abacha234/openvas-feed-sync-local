# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844349");
  script_cve_id("CVE-2015-9253", "CVE-2020-7059", "CVE-2020-7060");
  script_tag(name:"creation_date", value:"2020-02-20 04:00:23 +0000 (Thu, 20 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4279-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4279-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4279-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1863850");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0' package(s) announced via the USN-4279-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4279-1 fixed vulnerabilities in PHP. The updated packages caused a regression.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that PHP incorrectly handled certain scripts.
 An attacker could possibly use this issue to cause a denial of service.
 This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04 LTS.
 (CVE-2015-9253)

 It was discovered that PHP incorrectly handled certain inputs. An attacker
 could possibly use this issue to expose sensitive information.
 (CVE-2020-7059)

 It was discovered that PHP incorrectly handled certain inputs.
 An attacker could possibly use this issue to execute arbitrary code.
 This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
 and Ubuntu 19.10. (CVE-2020-7060)");

  script_tag(name:"affected", value:"'php7.0' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

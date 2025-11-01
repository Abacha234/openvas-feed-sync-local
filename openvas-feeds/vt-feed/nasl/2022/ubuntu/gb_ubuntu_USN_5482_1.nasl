# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845415");
  script_cve_id("CVE-2020-28984", "CVE-2021-44118", "CVE-2021-44120", "CVE-2021-44122", "CVE-2021-44123", "CVE-2022-26846", "CVE-2022-26847");
  script_tag(name:"creation_date", value:"2022-06-17 01:00:41 +0000 (Fri, 17 Jun 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:05:00 +0000 (Thu, 04 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-5482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5482-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5482-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip' package(s) announced via the USN-5482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SPIP incorrectly validated inputs. An authenticated
attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 18.04 LTS. (CVE-2020-28984)

Charles Fol and Theo Gordyjan discovered that SPIP is vulnerable to Cross
Site Scripting (XSS). If a user were tricked into browsing a malicious SVG
file, an attacker could possibly exploit this issue to execute arbitrary
code. This issue was only fixed in Ubuntu 21.10. (CVE-2021-44118,
CVE-2021-44120, CVE-2021-44122, CVE-2021-44123)

It was discovered that SPIP incorrectly handled certain forms. A remote
authenticated editor could possibly use this issue to execute arbitrary code,
and a remote unauthenticated attacker could possibly use this issue to obtain
sensitive information. (CVE-2022-26846, CVE-2022-26847)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 18.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

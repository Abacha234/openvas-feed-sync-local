# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845293");
  script_cve_id("CVE-2022-0843", "CVE-2022-26381", "CVE-2022-26382", "CVE-2022-26383", "CVE-2022-26384", "CVE-2022-26385", "CVE-2022-26387");
  script_tag(name:"creation_date", value:"2022-03-25 02:00:22 +0000 (Fri, 25 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5321-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5321-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5321-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1966306");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5321-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5321-1 fixed vulnerabilities in Firefox. The update introduced
several minor regressions. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, spoof the browser
 UI, bypass security restrictions, obtain sensitive information, or execute
 arbitrary code. (CVE-2022-0843, CVE-2022-26381, CVE-2022-26382,
 CVE-2022-26383, CVE-2022-26384, CVE-2022-26385)

 A TOCTOU bug was discovered when verifying addon signatures during
 install. A local attacker could potentially exploit this to trick a
 user into installing an addon with an invalid signature.
 (CVE-2022-26387)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

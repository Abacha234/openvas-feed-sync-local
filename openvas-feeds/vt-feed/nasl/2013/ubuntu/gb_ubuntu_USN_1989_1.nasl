# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841592");
  script_cve_id("CVE-2013-0900", "CVE-2013-2924");
  script_tag(name:"creation_date", value:"2013-10-18 03:46:08 +0000 (Fri, 18 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1989-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1989-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the USN-1989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ICU contained a race condition affecting multi-
threaded applications. If an application using ICU processed crafted data,
an attacker could cause it to crash or potentially execute arbitrary code
with the privileges of the user invoking the program. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 12.10. (CVE-2013-0900)

It was discovered that ICU incorrectly handled memory operations. If an
application using ICU processed crafted data, an attacker could cause it to
crash or potentially execute arbitrary code with the privileges of the user
invoking the program. (CVE-2013-2924)");

  script_tag(name:"affected", value:"'icu' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

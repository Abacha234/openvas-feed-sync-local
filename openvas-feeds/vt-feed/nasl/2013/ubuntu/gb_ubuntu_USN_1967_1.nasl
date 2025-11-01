# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841588");
  script_cve_id("CVE-2013-1443", "CVE-2013-4315");
  script_tag(name:"creation_date", value:"2013-10-03 04:51:46 +0000 (Thu, 03 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1967-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1967-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1967-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-1967-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Django incorrectly handled large passwords. A remote
attacker could use this issue to consume resources, resulting in a denial
of service. (CVE-2013-1443)

It was discovered that Django incorrectly handled ssi templates. An
attacker could use this issue to read arbitrary files. (CVE-2013-4315)

It was discovered that the Django is_safe_url utility function did not
restrict redirects to certain schemes. An attacker could possibly use this
issue to perform a cross-site scripting attack.");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

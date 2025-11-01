# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841551");
  script_cve_id("CVE-2013-2037");
  script_tag(name:"creation_date", value:"2013-09-12 06:19:03 +0000 (Thu, 12 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1948-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1948-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1948-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-httplib2' package(s) announced via the USN-1948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that httplib2 only validated SSL certificates on the
first request to a connection, and didn't report validation failures on
subsequent requests. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could possibly be exploited in certain
scenarios to alter or compromise confidential information in applications
that used the httplib2 library.");

  script_tag(name:"affected", value:"'python-httplib2' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

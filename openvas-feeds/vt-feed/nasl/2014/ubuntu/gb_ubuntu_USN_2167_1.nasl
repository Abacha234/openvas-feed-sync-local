# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841775");
  script_cve_id("CVE-2014-0138", "CVE-2014-0139");
  script_tag(name:"creation_date", value:"2014-04-15 04:13:13 +0000 (Tue, 15 Apr 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-2167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2167-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2167-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-2167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Holme discovered that libcurl incorrectly reused wrong connections
when using protocols other than HTTP and FTP. This could lead to the use of
unintended credentials, possibly exposing sensitive information.
(CVE-2014-0138)

Richard Moore discovered that libcurl incorrectly validated wildcard SSL
certificates that contain literal IP addresses. An attacker could possibly
exploit this to perform a machine-in-the-middle attack to view sensitive
information or alter encrypted communications. (CVE-2014-0139)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845009");
  script_cve_id("CVE-2021-22898", "CVE-2021-22924", "CVE-2021-22925");
  script_tag(name:"creation_date", value:"2021-07-23 03:00:32 +0000 (Fri, 23 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-16 17:23:00 +0000 (Mon, 16 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-5021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5021-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5021-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-5021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Harry Sintonen and Tomas Hoger discovered that curl incorrectly handled
TELNET connections when the -t option was used on the command line.
Uninitialized data possibly containing sensitive information could be sent
to the remote server, contrary to expectations. (CVE-2021-22898,
CVE-2021-22925)

Harry Sintonen discovered that curl incorrectly reused connections in the
connection pool. This could result in curl reusing the wrong connections.
(CVE-2021-22924)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

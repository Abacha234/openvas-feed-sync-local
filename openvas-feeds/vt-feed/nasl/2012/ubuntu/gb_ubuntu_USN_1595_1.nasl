# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841174");
  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_tag(name:"creation_date", value:"2012-10-05 04:14:04 +0000 (Fri, 05 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1595-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1595-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1595-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the USN-1595-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that libxslt incorrectly handled generate-id XPath
functions. If a user or automated system were tricked into processing a
specially crafted XSLT document, a remote attacker could obtain potentially
sensitive information. This issue only affected Ubuntu 8.04 LTS, Ubuntu
10.04 LTS and Ubuntu 11.04. (CVE-2011-1202)

It was discovered that libxslt incorrectly parsed certain patterns. If a
user or automated system were tricked into processing a specially crafted
XSLT document, a remote attacker could cause libxslt to crash, causing a
denial of service. (CVE-2011-3970)

Nicholas Gregoire discovered that libxslt incorrectly handled unexpected
DTD nodes. If a user or automated system were tricked into processing a
specially crafted XSLT document, a remote attacker could cause libxslt to
crash, causing a denial of service. (CVE-2012-2825)

Nicholas Gregoire discovered that libxslt incorrectly managed memory. If a
user or automated system were tricked into processing a specially crafted
XSLT document, a remote attacker could cause libxslt to crash, causing a
denial of service. (CVE-2012-2870)

Nicholas Gregoire discovered that libxslt incorrectly handled certain
transforms. If a user or automated system were tricked into processing a
specially crafted XSLT document, a remote attacker could cause libxslt to
crash, causing a denial of service, or possibly execute arbitrary code.
(CVE-2012-2871)

Cris Neckar discovered that libxslt incorrectly managed memory. If a user
or automated system were tricked into processing a specially crafted XSLT
document, a remote attacker could cause libxslt to crash, causing a denial
of service, or possibly execute arbitrary code. (CVE-2012-2893)");

  script_tag(name:"affected", value:"'libxslt' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

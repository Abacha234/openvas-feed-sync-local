# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840252");
  script_cve_id("CVE-2008-1767", "CVE-2008-2935");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-633-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-633-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-633-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the USN-633-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that long transformation matches in libxslt could
overflow. If an attacker were able to make an application linked against
libxslt process malicious XSL style sheet input, they could execute
arbitrary code with user privileges or cause the application to crash,
leading to a denial of service. (CVE-2008-1767)

Chris Evans discovered that the RC4 processing code in libxslt did not
correctly handle corrupted key information. If a remote attacker were
able to make an application linked against libxslt process malicious
XML input, they could crash the application, leading to a denial of
service. (CVE-2008-2935)");

  script_tag(name:"affected", value:"'libxslt' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

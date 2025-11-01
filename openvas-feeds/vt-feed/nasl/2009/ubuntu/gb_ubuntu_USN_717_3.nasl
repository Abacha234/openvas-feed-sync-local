# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63398");
  script_cve_id("CVE-2008-5510", "CVE-2009-0357");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-717-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-717-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-717-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-717-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kojima Hajime discovered that Firefox did not properly handle an escaped null
character. An attacker may be able to exploit this flaw to bypass script
sanitization. (CVE-2008-5510)

Wladimir Palant discovered that Firefox did not restrict access to cookies in
HTTP response headers. If a user were tricked into opening a malicious web
page, a remote attacker could view sensitive information. (CVE-2009-0357)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

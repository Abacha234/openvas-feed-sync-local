# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66307");
  script_cve_id("CVE-2009-2820");
  script_tag(name:"creation_date", value:"2009-11-23 19:51:51 +0000 (Mon, 23 Nov 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-856-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-856-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-856-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cupsys' package(s) announced via the USN-856-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aaron Sigel discovered that the CUPS web interface incorrectly protected
against cross-site scripting (XSS) and cross-site request forgery (CSRF)
attacks. If an authenticated user were tricked into visiting a malicious
website while logged into CUPS, a remote attacker could modify the CUPS
configuration and possibly steal confidential data.");

  script_tag(name:"affected", value:"'cups, cupsys' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

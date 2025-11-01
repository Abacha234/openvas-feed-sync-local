# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843463");
  script_cve_id("CVE-2018-6871");
  script_tag(name:"creation_date", value:"2018-03-01 07:14:47 +0000 (Thu, 01 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3579-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3579-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3579-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1751005");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-3579-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3579-1 fixed a vulnerability in LibreOffice. After upgrading, it was
no longer possible for LibreOffice to open documents from certain
locations outside of the user's home directory. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that =WEBSERVICE calls in a document could be used to
 read arbitrary files. If a user were tricked in to opening a specially
 crafted document, a remote attacker could exploit this to obtain sensitive
 information. (CVE-2018-6871)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

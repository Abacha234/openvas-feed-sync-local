# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65751");
  script_cve_id("CVE-2009-1382", "CVE-2009-2459");
  script_tag(name:"creation_date", value:"2009-10-13 16:25:40 +0000 (Tue, 13 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-844-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-844-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-844-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mimetex' package(s) announced via the USN-844-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that mimeTeX incorrectly handled certain long tags.
An attacker could exploit this with a crafted mimeTeX expression and cause
a denial of service or possibly execute arbitrary code. (CVE-2009-1382)

Chris Evans discovered that mimeTeX contained certain directives that may
be unsuitable for handling untrusted user input. This update fixed the
issue by disabling the \input and \counter tags. (CVE-2009-2459)");

  script_tag(name:"affected", value:"'mimetex' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

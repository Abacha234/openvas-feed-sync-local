# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841753");
  script_cve_id("CVE-2013-6474", "CVE-2013-6475", "CVE-2013-6476");
  script_tag(name:"creation_date", value:"2014-03-17 08:13:12 +0000 (Mon, 17 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2144-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2144-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-2144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered that the pdftoopvp filter bundled in the CUPS
package incorrectly handled memory. An attacker could possibly use this
issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6474, CVE-2013-6475)

Florian Weimer discovered that the pdftoopvp filter bundled in the CUPS
package did not restrict driver directories. An attacker could possibly use
this issue to execute arbitrary code with the privileges of the lp user.
(CVE-2013-6476)");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

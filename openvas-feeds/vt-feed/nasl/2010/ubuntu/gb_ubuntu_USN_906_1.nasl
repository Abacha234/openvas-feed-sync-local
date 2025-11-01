# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840396");
  script_cve_id("CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393");
  script_tag(name:"creation_date", value:"2010-03-05 11:48:43 +0000 (Fri, 05 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-906-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-906-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-906-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cupsys' package(s) announced via the USN-906-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the CUPS scheduler did not properly handle certain
network operations. A remote attacker could exploit this flaw and cause the
CUPS server to crash, resulting in a denial of service. This issue only
affected Ubuntu 8.04 LTS, 8.10, 9.04 and 9.10. (CVE-2009-3553,
CVE-2010-0302)

Ronald Volgers discovered that the CUPS lppasswd tool could be made to load
localized message strings from arbitrary files by setting an environment
variable. A local attacker could exploit this with a format-string
vulnerability leading to a root privilege escalation. The default compiler
options for Ubuntu 8.10, 9.04 and 9.10 should reduce this vulnerability to
a denial of service. (CVE-2010-0393)");

  script_tag(name:"affected", value:"'cups, cupsys' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

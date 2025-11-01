# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840765");
  script_cve_id("CVE-2011-1678", "CVE-2011-2724");
  script_tag(name:"creation_date", value:"2011-10-10 14:05:48 +0000 (Mon, 10 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1226-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1226-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1226-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils' package(s) announced via the USN-1226-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that cifs-utils incorrectly handled changes to the
mtab file. A local attacker could use this issue to corrupt the mtab file,
possibly leading to a denial of service. (CVE-2011-1678)

Jan Lieskovsky discovered that cifs-utils incorrectly filtered certain
strings being added to the mtab file. A local attacker could use this issue
to corrupt the mtab file, possibly leading to a denial of service.
(CVE-2011-2724)");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840323");
  script_cve_id("CVE-2007-6109", "CVE-2008-1694");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-607-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-607-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs21, emacs22' package(s) announced via the USN-607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Emacs did not account for precision when formatting
integers. If a user were tricked into opening a specially crafted file, an
attacker could cause a denial of service or possibly other unspecified
actions. This issue does not affect Ubuntu 8.04. (CVE-2007-6109)

Steve Grubb discovered that the vcdiff script as included in Emacs created
temporary files in an insecure way when used with SCCS. Local users could
exploit a race condition to create or overwrite files with the privileges
of the user invoking the program. (CVE-2008-1694)");

  script_tag(name:"affected", value:"'emacs21, emacs22' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

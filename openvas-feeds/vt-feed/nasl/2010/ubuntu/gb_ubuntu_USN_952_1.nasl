# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840447");
  script_cve_id("CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748");
  script_tag(name:"creation_date", value:"2010-06-25 10:25:26 +0000 (Fri, 25 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-952-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cupsys' package(s) announced via the USN-952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adrian Pastor and Tim Starling discovered that the CUPS web interface
incorrectly protected against cross-site request forgery (CSRF) attacks. If
an authenticated user were tricked into visiting a malicious website while
logged into CUPS, a remote attacker could modify the CUPS configuration and
possibly steal confidential data. (CVE-2010-0540)

It was discovered that CUPS did not properly handle memory allocations in
the texttops filter. If a user or automated system were tricked into
printing a crafted text file, a remote attacker could cause a denial of
service or possibly execute arbitrary code with privileges of the CUPS user
(lp). (CVE-2010-0542)

Luca Carettoni discovered that the CUPS web interface incorrectly handled
form variables. A remote attacker who had access to the CUPS web interface
could use this flaw to read a limited amount of memory from the cupsd
process and possibly obtain confidential data. (CVE-2010-1748)");

  script_tag(name:"affected", value:"'cups, cupsys' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

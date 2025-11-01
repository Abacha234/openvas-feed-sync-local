# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840582");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-2023", "CVE-2010-2024", "CVE-2010-4345", "CVE-2011-0017");
  script_tag(name:"creation_date", value:"2011-02-11 12:26:17 +0000 (Fri, 11 Feb 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1060-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1060-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1060-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim4' package(s) announced via the USN-1060-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Exim contained a design flaw in the way it processed
alternate configuration files. An attacker that obtained privileges of the
'Debian-exim' user could use an alternate configuration file to obtain
root privileges. (CVE-2010-4345)

It was discovered that Exim incorrectly handled certain return values when
handling logging. An attacker that obtained privileges of the 'Debian-exim'
user could use this flaw to obtain root privileges. (CVE-2011-0017)

Dan Rosenberg discovered that Exim incorrectly handled writable sticky-bit
mail directories. If Exim were configured in this manner, a local user
could use this flaw to cause a denial of service or possibly gain
privileges. This issue only applied to Ubuntu 6.06 LTS, 8.04 LTS, 9.10,
and 10.04 LTS. (CVE-2010-2023)

Dan Rosenberg discovered that Exim incorrectly handled MBX locking. If
Exim were configured in this manner, a local user could use this flaw to
cause a denial of service or possibly gain privileges. This issue only
applied to Ubuntu 6.06 LTS, 8.04 LTS, 9.10, and 10.04 LTS. (CVE-2010-2024)");

  script_tag(name:"affected", value:"'exim4' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65010");
  script_cve_id("CVE-2008-4577", "CVE-2008-5301", "CVE-2009-2632", "CVE-2009-3235");
  script_tag(name:"creation_date", value:"2009-10-06 00:49:40 +0000 (Tue, 06 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-838-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-838-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-838-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the USN-838-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ACL plugin in Dovecot would incorrectly handle
negative access rights. An attacker could exploit this flaw to access the
Dovecot server, bypassing the intended access restrictions. This only
affected Ubuntu 8.04 LTS. (CVE-2008-4577)

It was discovered that the ManageSieve service in Dovecot incorrectly
handled '..' in script names. A remote attacker could exploit this to read
and modify arbitrary sieve files on the server. This only affected Ubuntu
8.10. (CVE-2008-5301)

It was discovered that the Sieve plugin in Dovecot incorrectly handled
certain sieve scripts. An authenticated user could exploit this with a
crafted sieve script to cause a denial of service or possibly execute
arbitrary code. (CVE-2009-2632, CVE-2009-3235)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841218");
  script_cve_id("CVE-2012-4571");
  script_tag(name:"creation_date", value:"2012-11-23 06:20:53 +0000 (Fri, 23 Nov 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1634-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1634-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1004845");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-keyring' package(s) announced via the USN-1634-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dwayne Litzenberger discovered that Python Keyring's CryptedFileKeyring
file format used weak cryptography. A local attacker may use this issue to
brute-force CryptedFileKeyring keyring files. This issue only affected
Ubuntu 11.10 and Ubuntu 12.04 LTS. (CVE-2012-4571)

It was discovered that Python Keyring created keyring files with insecure
permissions. A local attacker could use this issue to access keyring files
belonging to other users.");

  script_tag(name:"affected", value:"'python-keyring' package(s) on Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

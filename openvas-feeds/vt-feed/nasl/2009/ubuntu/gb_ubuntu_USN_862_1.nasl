# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66338");
  script_cve_id("CVE-2008-7068", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3557", "CVE-2009-3558", "CVE-2009-4017", "CVE-2009-4018");
  script_tag(name:"creation_date", value:"2009-12-03 21:10:42 +0000 (Thu, 03 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-862-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-862-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-862-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Maksymilian Arciemowicz discovered that PHP did not properly validate
arguments to the dba_replace function. If a script passed untrusted input
to the dba_replace function, an attacker could truncate the database. This
issue only applied to Ubuntu 6.06 LTS, 8.04 LTS, and 8.10. (CVE-2008-7068)

It was discovered that PHP's php_openssl_apply_verification_policy
function did not correctly handle SSL certificates with zero bytes in the
Common Name. A remote attacker could exploit this to perform a
machine-in-the-middle attack to view sensitive information or alter
encrypted communications. (CVE-2009-3291)

It was discovered that PHP did not properly handle certain malformed images
when being parsed by the Exif module. A remote attacker could exploit this
flaw and cause the PHP server to crash, resulting in a denial of service.
(CVE-2009-3292)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the tempnam function. An attacker could exploit this issue
to bypass safe_mode restrictions. (CVE-2009-3557)

Grzegorz Stachowiak discovered that PHP did not properly enforce
restrictions in the posix_mkfifo function. An attacker could exploit this
issue to bypass open_basedir restrictions. (CVE-2009-3558)

Bogdan Calin discovered that PHP did not limit the number of temporary
files created when handling multipart/form-data POST requests. A remote
attacker could exploit this flaw and cause the PHP server to consume all
available resources, resulting in a denial of service. (CVE-2009-4017)

ATTENTION: This update changes previous PHP behaviour by limiting the
number of files in a POST request to 50. This may be increased by adding a
'max_file_uploads' directive to the php.ini configuration file.

It was discovered that PHP did not properly enforce restrictions in the
proc_open function. An attacker could exploit this issue to bypass
safe_mode_protected_env_vars restrictions and possibly execute arbitrary
code with application privileges. (CVE-2009-4018)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

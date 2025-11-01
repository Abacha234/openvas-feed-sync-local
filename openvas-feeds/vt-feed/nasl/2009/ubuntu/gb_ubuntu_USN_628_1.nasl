# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840283");
  script_cve_id("CVE-2007-4782", "CVE-2007-4850", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-0599", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2371", "CVE-2008-2829");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-628-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-628-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-628-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-628-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP did not properly check the length of the
string parameter to the fnmatch function. An attacker could cause a
denial of service in the PHP interpreter if a script passed untrusted
input to the fnmatch function. (CVE-2007-4782)

Maksymilian Arciemowicz discovered a flaw in the cURL library that
allowed safe_mode and open_basedir restrictions to be bypassed. If a
PHP application were tricked into processing a bad file:// request,
an attacker could read arbitrary files. (CVE-2007-4850)

Rasmus Lerdorf discovered that the htmlentities and htmlspecialchars
functions did not correctly stop when handling partial multibyte
sequences. A remote attacker could exploit this to read certain areas
of memory, possibly gaining access to sensitive information. This
issue affects Ubuntu 8.04 LTS, and an updated fix is included for
Ubuntu 6.06 LTS, 7.04 and 7.10. (CVE-2007-5898)

It was discovered that the output_add_rewrite_var function would
sometimes leak session id information to forms targeting remote URLs.
Malicious remote sites could use this information to gain access to a
PHP application user's login credentials. This issue only affects
Ubuntu 8.04 LTS. (CVE-2007-5899)

It was discovered that PHP did not properly calculate the length of
PATH_TRANSLATED. If a PHP application were tricked into processing
a malicious URI, and attacker may be able to execute arbitrary code
with application privileges. (CVE-2008-0599)

An integer overflow was discovered in the php_sprintf_appendstring
function. Attackers could exploit this to cause a denial of service.
(CVE-2008-1384)

Andrei Nigmatulin discovered stack-based overflows in the FastCGI SAPI
of PHP. An attacker may be able to leverage this issue to perform
attacks against PHP applications. (CVE-2008-2050)

It was discovered that the escapeshellcmd did not properly process
multibyte characters. An attacker may be able to bypass quoting
restrictions and possibly execute arbitrary code with application
privileges. (CVE-2008-2051)

It was discovered that the GENERATE_SEED macro produced a predictable
seed under certain circumstances. Attackers may by able to easily
predict the results of the rand and mt_rand functions.
(CVE-2008-2107, CVE-2008-2108)

Tavis Ormandy discovered that the PCRE library did not correctly
handle certain in-pattern options. An attacker could cause PHP
applications using pcre to crash, leading to a denial of service.
USN-624-1 fixed vulnerabilities in the pcre3 library. This update
provides the corresponding update for PHP. (CVE-2008-2371)

It was discovered that php_imap used obsolete API calls. If a PHP
application were tricked into processing a malicious IMAP request,
an attacker could cause a denial of service or possibly execute code
with application privileges. (CVE-2008-2829)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

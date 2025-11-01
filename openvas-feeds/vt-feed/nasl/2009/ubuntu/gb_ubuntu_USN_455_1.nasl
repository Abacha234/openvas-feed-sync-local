# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840068");
  script_cve_id("CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1718", "CVE-2007-1824", "CVE-2007-1887", "CVE-2007-1888", "CVE-2007-1900");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Ubuntu: Security Advisory (USN-455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-455-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-455-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser discovered multiple vulnerabilities in the 'Month of PHP
bugs'.

The substr_compare() function did not sufficiently verify its length
argument. This might be exploited to read otherwise unaccessible
memory, which might lead to information disclosure. (CVE-2007-1375)

The shared memory (shmop) functions did not verify resource types,
thus they could be called with a wrong resource type that might
contain user supplied data. This could be exploited to read and write
arbitrary memory addresses of the PHP interpreter. This issue does
not affect Ubuntu 7.04. (CVE-2007-1376)

The php_binary handler of the session extension was missing a boundary
check. When unserializing overly long variable names this could be
exploited to read up to 126 bytes of memory, which might lead to
information disclosure. (CVE-2007-1380)

The internal array_user_key_compare() function, as used for example by
the PHP function uksort(), incorrectly handled memory unreferencing of
its arguments. This could have been exploited to execute arbitrary
code with the privileges of the PHP interpreter, and thus
circumventing any disable_functions, open_basedir, or safe_mode
restrictions. (CVE-2007-1484)

The session_regenerate_id() function did not properly clean up the
former session identifier variable. This could be exploited to crash
the PHP interpreter, possibly also remotely. (CVE-2007-1521)

Under certain conditions the mb_parse_str() could cause the
register_globals configuration option to become permanently enabled.
This opened an attack vector for a large and common class of
vulnerabilities. (CVE-2007-1583)

The session extension did not set the correct reference count value
for the session variables. By unsetting _SESSION and HTTP_SESSION_VARS
(or tricking a PHP script into doing that) this could be exploited to
execute arbitrary code with the privileges of the PHP interpreter. This
issue does not affect Ubuntu 7.04. (CVE-2007-1700)

The mail() function did not correctly escape control characters in
multiline email headers. This could be remotely exploited to inject
arbitrary email headers. (CVE-2007-1718)

The php_stream_filter_create() function had an off-by-one buffer
overflow in the handling of wildcards. This could be exploited to
remotely crash the PHP interpreter. This issue does not affect Ubuntu
7.04. (CVE-2007-1824)

When calling the sqlite_udf_decode_binary() with special arguments, a
buffer overflow happened. Depending on the application this could be
locally or remotely exploited to execute arbitrary code with the
privileges of the PHP interpreter. (CVE-2007-1887 CVE-2007-1888)

The FILTER_VALIDATE_EMAIL filter extension used a wrong
regular expression that allowed injecting a newline character at the
end of the email string. This could be exploited to inject
arbitrary email headers. This issue only affects Ubuntu 7.04.
(CVE-2007-1900)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

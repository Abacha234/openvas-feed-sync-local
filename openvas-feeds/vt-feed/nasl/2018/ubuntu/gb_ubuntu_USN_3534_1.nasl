# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843422");
  script_cve_id("CVE-2017-1000408", "CVE-2017-1000409", "CVE-2017-15670", "CVE-2017-15804", "CVE-2017-16997", "CVE-2017-17426", "CVE-2018-1000001");
  script_tag(name:"creation_date", value:"2018-01-18 06:36:12 +0000 (Thu, 18 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3534-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3534-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3534-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-3534-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GNU C library did not properly handle all of
the possible return values from the kernel getcwd(2) syscall. A local
attacker could potentially exploit this to execute arbitrary code in setuid
programs and gain administrative privileges. (CVE-2018-1000001)

A memory leak was discovered in the _dl_init_paths() function in the GNU
C library dynamic loader. A local attacker could potentially exploit this
with a specially crafted value in the LD_HWCAP_MASK environment variable,
in combination with CVE-2017-1000409 and another vulnerability on a system
with hardlink protections disabled, in order to gain administrative
privileges. (CVE-2017-1000408)

A heap-based buffer overflow was discovered in the _dl_init_paths()
function in the GNU C library dynamic loader. A local attacker could
potentially exploit this with a specially crafted value in the
LD_LIBRARY_PATH environment variable, in combination with CVE-2017-1000408
and another vulnerability on a system with hardlink protections disabled,
in order to gain administrative privileges. (CVE-2017-1000409)

An off-by-one error leading to a heap-based buffer overflow was discovered
in the GNU C library glob() implementation. An attacker could potentially
exploit this to cause a denial of service or execute arbitrary code via a
maliciously crafted pattern. (CVE-2017-15670)

A heap-based buffer overflow was discovered during unescaping of user names
with the ~ operator in the GNU C library glob() implementation. An attacker
could potentially exploit this to cause a denial of service or execute
arbitrary code via a maliciously crafted pattern. (CVE-2017-15804)

It was discovered that the GNU C library dynamic loader mishandles RPATH
and RUNPATH containing $ORIGIN for privileged (setuid or AT_SECURE)
programs. A local attacker could potentially exploit this by providing a
specially crafted library in the current working directory in order to
gain administrative privileges. (CVE-2017-16997)

It was discovered that the GNU C library malloc() implementation could
return a memory block that is too small if an attempt is made to allocate
an object whose size is close to SIZE_MAX, resulting in a heap-based
overflow. An attacker could potentially exploit this to cause a denial of
service or execute arbitrary code. This issue only affected Ubuntu 17.10.
(CVE-2017-17426)");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

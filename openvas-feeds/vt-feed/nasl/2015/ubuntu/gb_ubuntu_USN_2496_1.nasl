# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842088");
  script_cve_id("CVE-2012-3509", "CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_tag(name:"creation_date", value:"2015-02-10 04:30:54 +0000 (Tue, 10 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2496-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2496-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2496-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-2496-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michal Zalewski discovered that the setup_group function in libbfd in
GNU binutils did not properly check group headers in ELF files. An
attacker could use this to craft input that could cause a denial
of service (application crash) or possibly execute arbitrary code.
(CVE-2014-8485)

Hanno Bock discovered that the _bfd_XXi_swap_aouthdr_in function
in libbfd in GNU binutils allowed out-of-bounds writes. An
attacker could use this to craft input that could cause a denial
of service (application crash) or possibly execute arbitrary code.
(CVE-2014-8501)

Hanno Bock discovered a heap-based buffer overflow in the
pe_print_edata function in libbfd in GNU binutils. An attacker
could use this to craft input that could cause a denial of service
(application crash) or possibly execute arbitrary code. (CVE-2014-8502)

Alexander Cherepanov discovered multiple directory traversal
vulnerabilities in GNU binutils. An attacker could use this to craft
input that could delete arbitrary files. (CVE-2014-8737)

Alexander Cherepanov discovered the _bfd_slurp_extended_name_table
function in libbfd in GNU binutils allowed invalid writes when handling
extended name tables in an archive. An attacker could use this to
craft input that could cause a denial of service (application crash)
or possibly execute arbitrary code. (CVE-2014-8738)

Hanno Bock discovered a stack-based buffer overflow in the ihex_scan
function in libbfd in GNU binutils. An attacker could use this
to craft input that could cause a denial of service (application
crash). (CVE-2014-8503)

Michal Zalewski discovered a stack-based buffer overflow in the
srec_scan function in libbfd in GNU binutils. An attacker could
use this to craft input that could cause a denial of service
(application crash), the GNU C library's Fortify Source printf
protection should prevent the possibility of executing arbitrary code.
(CVE-2014-8504)

Michal Zalewski discovered that the srec_scan function in libbfd
in GNU binutils allowed out-of-bounds reads. An attacker could
use this to craft input to cause a denial of service. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 10.04
LTS. (CVE-2014-8484)

Sang Kil Cha discovered multiple integer overflows in the
_objalloc_alloc function and objalloc_alloc macro in binutils. This
could allow an attacker to cause a denial of service (application
crash). This issue only affected Ubuntu 12.04 LTS and Ubuntu 10.04 LTS.
(CVE-2012-3509)

Alexander Cherepanov and Hanno Bock discovered multiple additional
out-of-bounds reads and writes in GNU binutils. An attacker could use
these to craft input that could cause a denial of service (application
crash) or possibly execute arbitrary code. A few of these issues may
be limited in exposure to a denial of service (application abort)
by the GNU C library's Fortify Source printf protection.

The strings(1) utility in GNU binutils used libbfd by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

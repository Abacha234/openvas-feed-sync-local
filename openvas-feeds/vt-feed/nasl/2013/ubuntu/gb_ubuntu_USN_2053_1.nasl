# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841653");
  script_cve_id("CVE-2013-5609", "CVE-2013-5613", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6673");
  script_tag(name:"creation_date", value:"2013-12-17 06:37:42 +0000 (Tue, 17 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 14:39:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2053-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2053-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1258653");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Turner, Bobby Holley, Jesse Ruderman and Christian Holler discovered
multiple memory safety issues in Thunderbird. If a user were tricked in to
opening a specially crafted message with scripting enabled, an attacker
could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2013-5609)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
event listeners. If a user had enabled scripting, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5616)

A use-after-free was discovered in the table editing interface. An
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2013-5618)

Tyson Smith and Jesse Schwartzentruber discovered a crash when inserting
an ordered list in to a document using script. If a user had enabled
scripting, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-6671)

Sijie Xia discovered that trust settings for built-in EV root certificates
were ignored under certain circumstances, removing the ability for a user
to manually untrust certificates from specific authorities.
(CVE-2013-6673)

Tyson Smith, Jesse Schwartzentruber and Atte Kettunen discovered a
use-after-free in functions for synthetic mouse movement handling. If a
user had enabled scripting, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2013-5613)

Eric Faust discovered that GetElementIC typed array stubs can be generated
outside observed typesets. If a user had enabled scripting, an attacker
could possibly exploit this to cause undefined behaviour with a potential
security impact. (CVE-2013-5615)

Michal Zalewski discovered several issues with JPEG image handling. An
attacker could potentially exploit these to obtain sensitive information.
(CVE-2013-6629, CVE-2013-6630)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

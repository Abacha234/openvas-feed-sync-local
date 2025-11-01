# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842895");
  script_cve_id("CVE-2016-2827", "CVE-2016-5256", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5273", "CVE-2016-5274", "CVE-2016-5275", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2016-09-23 03:42:01 +0000 (Fri, 23 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3076-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3076-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Atte Kettunen discovered an out-of-bounds read when handling certain
Content Security Policy (CSP) directives in some circumstances. If a user
were tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash. (CVE-2016-2827)

Christoph Diehl, Christian Holler, Gary Kwong, Nathan Froyd, Honza Bambas,
Seth Fowler, Michael Smith, Andrew McCreight, Dan Minor, Byron Campen, Jon
Coppeard, Steve Fink, Tyson Smith, and Carsten Book discovered multiple
memory safety issues in Firefox. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5256, CVE-2016-5257)

Atte Kettunen discovered a heap buffer overflow during text conversion
with some unicode characters. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5270)

Abhishek Arya discovered an out of bounds read during the processing of
text runs in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash. (CVE-2016-5271)

Abhishek Arya discovered a bad cast when processing layout with input
elements in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this to
cause a denial of service via application crash, or execute arbitrary
code. (CVE-2016-5272)

A crash was discovered in accessibility. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to execute arbitrary code. (CVE-2016-5273)

A use-after-free was discovered in web animations during restyling. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code. (CVE-2016-5274)

A buffer overflow was discovered when working with empty filters during
canvas rendering. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-5275)

A use-after-free was discovered in accessibility. If a user were tricked
in to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5276)

A use-after-free was discovered in web animations when destroying a
timeline. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

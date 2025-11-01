# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844268");
  script_cve_id("CVE-2019-11755", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903");
  script_tag(name:"creation_date", value:"2019-12-11 03:01:29 +0000 (Wed, 11 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4202-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4202-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4202-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1854150");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4202-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4202-1 fixed vulnerabilities in Thunderbird. After upgrading, Thunderbird
created a new profile for some users. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that a specially crafted S/MIME message with an inner
 encryption layer could be displayed as having a valid signature in some
 circumstances, even if the signer had no access to the encrypted message.
 An attacker could potentially exploit this to spoof the message author.
 (CVE-2019-11755)

 Multiple security issues were discovered in Thunderbird. If a user were
 tricked in to opening a specially crafted website in a browsing context,
 an attacker could potentially exploit these to cause a denial of service,
 bypass security restrictions, bypass same-origin restrictions, conduct
 cross-site scripting (XSS) attacks, or execute arbitrary code.
 (CVE-2019-11757, CVE-2019-11758, CVE-2019-11759, CVE-2019-11760,
 CVE-2019-11761, CVE-2019-11762, CVE-2019-11763, CVE-2019-11764)

 A heap overflow was discovered in the expat library in Thunderbird. If a
 user were tricked in to opening a specially crafted message, an attacker
 could potentially exploit this to cause a denial of service, or execute
 arbitrary code. (CVE-2019-15903)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

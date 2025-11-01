# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844392");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-20503", "CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6798", "CVE-2020-6800", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814", "CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825");
  script_tag(name:"creation_date", value:"2020-04-14 03:00:24 +0000 (Tue, 14 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 16:07:00 +0000 (Fri, 01 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-4328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4328-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4328-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Message ID calculation was based on uninitialized
data. An attacker could potentially exploit this to obtain sensitive
information. (CVE-2020-6792)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information, or execute arbitrary code. (CVE-2020-6793, CVE-2020-6795,
CVE-2020-6822)

It was discovered that if a user saved passwords before Thunderbird 60
and then later set a master password, an unencrypted copy of these
passwords would still be accessible. A local user could exploit this to
obtain sensitive information. (CVE-2020-6794)

Multiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
conduct cross-site scripting (XSS) attacks, obtain sensitive information,
or execute arbitrary code. (CVE-2019-20503, CVE-2020-6798, CVE-2020-6800,
CVE-2020-6805, CVE-2020-6806, CVE-2020-6807, CVE-2020-6812, CVE-2020-6814,
CVE-2020-6819, CVE-2020-6820, CVE-2020-6821, CVE-2020-6825)

It was discovered that the Devtools' 'Copy as cURL' feature did not
fully escape website-controlled data. If a user were tricked in to using
the 'Copy as cURL' feature to copy and paste a command with specially
crafted data in to a terminal, an attacker could potentially exploit this
to execute arbitrary commands via command injection. (CVE-2020-6811)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844881");
  script_cve_id("CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23983", "CVE-2021-23984", "CVE-2021-23985", "CVE-2021-23986", "CVE-2021-23987", "CVE-2021-23988");
  script_tag(name:"creation_date", value:"2021-03-26 04:00:38 +0000 (Fri, 26 Mar 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 14:15:00 +0000 (Thu, 24 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4893-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4893-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information, or execute arbitrary code. (CVE-2021-23981, CVE-2021-23982,
CVE-2021-23983, CVE-2021-23987, CVE-2021-23988)

It was discovered that extensions could open popup windows with control
of the window title in some circumstances. If a user were tricked into
installing a specially crafted extension, an attacker could potentially
exploit this to spook a website and trick the user into providing
credentials. (CVE-2021-23984)

It was discovered that the DevTools remote debugging feature could be
enabled without an indication to the user. If a local attacker could
modify the browser configuration, a remote attacker could potentially
exploit this to obtain sensitive information. (CVE-2021-23985)

It was discovered that extensions could read the response of cross
origin requests in some circumstances. If a user were tricked into
installing a specially crafted extension, an attacker could potentially
exploit this to obtain sensitive information. (CVE-2021-23986)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844164");
  script_cve_id("CVE-2019-11734", "CVE-2019-11735", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11741", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11752", "CVE-2019-5849", "CVE-2019-9812");
  script_tag(name:"creation_date", value:"2019-09-05 02:00:38 +0000 (Thu, 05 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-04 18:15:00 +0000 (Fri, 04 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4122-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4122-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4122-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4122-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to obtain sensitive information, bypass Content
Security Policy (CSP) protections, bypass same-origin restrictions,
conduct cross-site scripting (XSS) attacks, cause a denial of service, or
execute arbitrary code. (CVE-2019-5849, CVE-2019-11734, CVE-2019-11735,
CVE-2019-11737, CVE-2019-11738, CVE-2019-11740, CVE-2019-11742,
CVE-2019-11743, CVE-2019-11744, CVE-2019-11746, CVE-2019-11748,
CVE-2019-11749, CVE-2019-11750, CVE-2019-11752)

It was discovered that a compromised content process could log in to a
malicious Firefox Sync account. An attacker could potentially exploit
this, in combination with another vulnerability, to disable the sandbox.
(CVE-2019-9812)

It was discovered that addons.mozilla.org and accounts.firefox.com could
be loaded in to the same content process. An attacker could potentially
exploit this, in combination with another vulnerability that allowed a
cross-site scripting (XSS) attack, to modify browser settings.
(CVE-2019-11741)

It was discovered that the 'Forget about this site' feature in the history
pane removes HTTP Strict Transport Security (HSTS) settings for sites on
the pre-load list. An attacker could potentially exploit this to bypass
the protections offered by HSTS. (CVE-2019-11747)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

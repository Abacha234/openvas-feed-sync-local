# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60575");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1485");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1485");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0412

Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren and Paul Nickerson discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-0413

Carsten Book, Wesley Garland, Igor Bukanov, moz_bug_r_a4, shutdown, Philip Taylor and tgirmann discovered crashes in the JavaScript engine, which might allow the execution of arbitrary code.

CVE-2008-0415

moz_bug_r_a4 and Boris Zbarsky discovered several vulnerabilities in JavaScript handling, which could allow privilege escalation.

CVE-2008-0418

Gerry Eisenhaur and moz_bug_r_a4 discovered that a directory traversal vulnerability in chrome: URI handling could lead to information disclosure.

CVE-2008-0419

David Bloom discovered a race condition in the image handling of designMode elements, which can lead to information disclosure and potentially the execution of arbitrary code.

CVE-2008-0591

Michal Zalewski discovered that timers protecting security-sensitive dialogs (by disabling dialog elements until a timeout is reached) could be bypassed by window focus changes through JavaScript.

The Mozilla products from the old stable distribution (sarge) are no longer supported with security updates.

For the stable distribution (etch), these problems have been fixed in version 1.5.0.13+1.5.0.15b.dfsg1-0etch2.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
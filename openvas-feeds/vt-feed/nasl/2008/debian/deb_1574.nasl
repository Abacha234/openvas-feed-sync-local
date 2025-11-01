# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61025");
  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237");
  script_tag(name:"creation_date", value:"2008-05-27 13:41:50 +0000 (Tue, 27 May 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1574)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1574");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1574");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1574 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1233

moz_bug_r_a4 discovered that variants of CVE-2007-3738 and CVE-2007-5338 allow the execution of arbitrary code through XPCNativeWrapper.

CVE-2008-1234

moz_bug_r_a4 discovered that insecure handling of event handlers could lead to cross-site scripting.

CVE-2008-1235

Boris Zbarsky, Johnny Stenback and moz_bug_r_a4 discovered that incorrect principal handling could lead to cross-site scripting and the execution of arbitrary code.

CVE-2008-1236

Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett and Mats Palmgren discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-1237

georgi, tgirmann and Igor Bukanov discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
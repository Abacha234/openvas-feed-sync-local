# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68088");
  script_cve_id("CVE-2010-2760", "CVE-2010-2763", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2106)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2106");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2106");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-2106 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2760, CVE-2010-3167, CVE-2010-3168 Implementation errors in XUL processing allow the execution of arbitrary code.

CVE-2010-2763

An implementation error in the XPCSafeJSObjectWrapper wrapper allows the bypass of the same origin policy.

CVE-2010-2765

An integer overflow in frame handling allows the execution of arbitrary code.

CVE-2010-2766

An implementation error in DOM handling allows the execution of arbitrary code.

CVE-2010-2767

Incorrect pointer handling in the plugin code allow the execution of arbitrary code.

CVE-2010-2768

Incorrect handling of an object tag may lead to the bypass of cross site scripting filters.

CVE-2010-2769

Incorrect copy and paste handling could lead to cross site scripting.

CVE-2010-3169

Crashes in the layout engine may lead to the execution of arbitrary code.

For the stable distribution (lenny), these problems have been fixed in version 1.9.0.19-4.

For the unstable distribution (sid), these problems have been fixed in version 3.5.12-1 of the iceweasel source package (which now builds the xulrunner library binary packages).

For the experimental distribution, these problems have been fixed in version 3.6.9-1 of the iceweasel source package (which now builds the xulrunner library binary packages).

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
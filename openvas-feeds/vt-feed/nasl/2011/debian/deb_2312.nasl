# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70401");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2312)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2312");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2312");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2312 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Iceape internet suite, an unbranded version of Seamonkey:

CVE-2011-2372

Mariusz Mlynski discovered that websites could open a download dialog -- which has open as the default action --, while a user presses the ENTER key.

CVE-2011-2995

Benjamin Smedberg, Bob Clary and Jesse Ruderman discovered crashes in the rendering engine, which could lead to the execution of arbitrary code.

CVE-2011-2998

Mark Kaplan discovered an integer underflow in the JavaScript engine, which could lead to the execution of arbitrary code.

CVE-2011-2999

Boris Zbarsky discovered that incorrect handling of the window.location object could lead to bypasses of the same-origin policy.

CVE-2011-3000

Ian Graham discovered that multiple Location headers might lead to CRLF injection.

The oldstable distribution (lenny) is not affected. The iceape package only provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in version 2.0.11-8. This update also marks the compromised DigiNotar root certs as revoked rather then untrusted.

For the unstable distribution (sid), this problem has been fixed in version 2.0.14-8.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
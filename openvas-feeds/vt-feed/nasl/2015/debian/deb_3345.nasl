# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703345");
  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_tag(name:"creation_date", value:"2015-08-28 22:00:00 +0000 (Fri, 28 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3345");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3345");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-3345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Iceweasel, Debian's version of the Mozilla Firefox web browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-4497

Jean-Max Reymond and Ucha Gobejishvili discovered a use-after-free vulnerability which occurs when resizing of a canvas element is triggered in concert with style changes. A web page containing malicious content can cause Iceweasel to crash, or potentially, execute arbitrary code with the privileges of the user running Iceweasel.

CVE-2015-4498

Bas Venis reported a flaw in the handling of add-ons installation. A remote attacker can take advantage of this flaw to bypass the add-on installation prompt and trick a user into installing an add-on from a malicious source.

For the oldstable distribution (wheezy), these problems have been fixed in version 38.2.1esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 38.2.1esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 38.2.1esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
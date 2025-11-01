# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60210");
  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1466");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1466");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfree86, xorg-server' package(s) announced via the DSA-1466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The X.org fix for CVE-2007-6429 introduced a regression in the MIT-SHM extension, which prevented the start of a few applications. This update provides updated packages for the xfree86 version included in Debian old stable (sarge) in addition to the fixed packages for Debian stable (etch), which were provided in DSA 1466-2.

For reference the original advisory text below:

Several local vulnerabilities have been discovered in the X.Org X server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5760

regenrecht discovered that missing input sanitising within the XFree86-Misc extension may lead to local privilege escalation.

CVE-2007-5958

It was discovered that error messages of security policy file handling may lead to a minor information leak disclosing the existence of files otherwise inaccessible to the user.

CVE-2007-6427

regenrecht discovered that missing input sanitising within the XInput-Misc extension may lead to local privilege escalation.

CVE-2007-6428

regenrecht discovered that missing input sanitising within the TOG-CUP extension may lead to disclosure of memory contents.

CVE-2007-6429

regenrecht discovered that integer overflows in the EVI and MIT-SHM extensions may lead to local privilege escalation.

CVE-2008-0006

It was discovered that insufficient validation of PCF fonts could lead to local privilege escalation.

For the oldstable distribution (sarge), this problem has been fixed in version 4.3.0.dfsg.1-14sarge7 of xfree86.

For the stable distribution (etch), this problem has been fixed in version 1.1.1-21etch3 of xorg-server and 1.2.2-2.etch1 of libxfont.

For the unstable distribution (sid), this problem has been fixed in version 2:1.4.1~git20080118-1 of xorg-server and version 1:1.3.1-2 of libxfont.

We recommend that you upgrade your X.org/Xfree86 packages.");

  script_tag(name:"affected", value:"'xfree86, xorg-server' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
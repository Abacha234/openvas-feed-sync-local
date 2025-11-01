# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703394");
  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_tag(name:"creation_date", value:"2015-11-04 23:00:00 +0000 (Wed, 04 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3394)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3394");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3394");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libreoffice' package(s) announced via the DSA-3394 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in LibreOffice, a full-featured office productivity:

CVE-2015-4551

Federico Scrinzi discovered an information leak in the handling of ODF documents. Quoting from : The LinkUpdateMode feature controls whether documents inserted into Writer or Calc via links will either not get updated, or prompt to update, or automatically update, when the parent document is loaded. The configuration of this option was stored in the document. That flawed approach enabled documents to be crafted with links to plausible targets on the victims host computer. The contents of those automatically inserted after load links can be concealed in hidden sections and retrieved by the attacker if the document is saved and returned to sender, or via http requests if the user has selected lower security settings for that document.

CVE-2015-5212

A buffer overflow in parsing the printer setup information in ODF documents may result in the execution of arbitrary code.

CVE-2015-5213 / CVE-2015-5214 A buffer overflow and an integer overflow in parsing Microsoft Word documents may result in the execution of arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 1:3.5.4+dfsg2-0+deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 1:4.3.3-2+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 1:5.0.2-1.

For the unstable distribution (sid), these problems have been fixed in version 1:5.0.2-1.

We recommend that you upgrade your libreoffice packages.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69111");
  script_cve_id("CVE-2008-5183", "CVE-2009-3553", "CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748", "CVE-2010-2431", "CVE-2010-2432", "CVE-2010-2941");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2176");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2176");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cups' package(s) announced via the DSA-2176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Common UNIX Printing System:

CVE-2008-5183

A null pointer dereference in RSS job completion notifications could lead to denial of service.

CVE-2009-3553

It was discovered that incorrect file descriptor handling could lead to denial of service.

CVE-2010-0540

A cross-site request forgery vulnerability was discovered in the web interface.

CVE-2010-0542

Incorrect memory management in the filter subsystem could lead to denial of service.

CVE-2010-1748

Information disclosure in the web interface.

CVE-2010-2431

Emmanuel Bouillon discovered a symlink vulnerability in handling of cache files.

CVE-2010-2432

Denial of service in the authentication code.

CVE-2010-2941

Incorrect memory management in the IPP code could lead to denial of service or the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in version 1.3.8-1+lenny9.

The stable distribution (squeeze) and the unstable distribution (sid) had already been fixed prior to the initial Squeeze release.

We recommend that you upgrade your cups packages.");

  script_tag(name:"affected", value:"'cups' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
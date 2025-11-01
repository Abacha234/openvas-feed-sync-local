# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62839");
  script_cve_id("CVE-2008-5286");
  script_tag(name:"creation_date", value:"2008-12-10 04:23:56 +0000 (Wed, 10 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1677)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1677");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1677");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cupsys' package(s) announced via the DSA-1677 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow has been discovered in the image validation code of cupsys, the Common UNIX Printing System. An attacker could trigger this bug by supplying a malicious graphic that could lead to the execution of arbitrary code.

For the stable distribution (etch) this problem has been fixed in version 1.2.7-4etch6.

For testing distribution (lenny) this issue will be fixed soon.

For the unstable distribution (sid) this problem has been fixed in version 1.3.8-1lenny4.

We recommend that you upgrade your cupsys packages.");

  script_tag(name:"affected", value:"'cupsys' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
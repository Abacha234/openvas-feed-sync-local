# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69106");
  script_cve_id("CVE-2010-2795", "CVE-2010-2796", "CVE-2010-3690", "CVE-2010-3691", "CVE-2010-3692");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2172");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2172");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-2172 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpCAS, a CAS client library for PHP. The Moodle course management system includes a copy of phpCAS.

For the oldstable distribution (lenny), this problem has been fixed in version 1.8.13-3.

The stable distribution (squeeze) already contains a fixed version of phpCAS.

The unstable distribution (sid) already contains a fixed version of phpCAS.

We recommend that you upgrade your moodle packages.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
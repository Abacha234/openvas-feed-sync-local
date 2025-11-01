# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842114");
  script_cve_id("CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0836");
  script_tag(name:"creation_date", value:"2015-03-04 04:44:46 +0000 (Wed, 04 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2506-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2506-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2506-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2506-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Armin Razmdjou discovered that contents of locally readable files could
be made available via manipulation of form autocomplete in some
circumstances. If a user were tricked in to opening a specially crafted
message with scripting enabled, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2015-0822)

Abhishek Arya discovered an out-of-bounds read and write when rendering
SVG content in some circumstances. If a user were tricked in to opening
a specially crafted message with scripting enabled, an attacker could
potentially exploit this to obtain sensitive information. (CVE-2015-0827)

Paul Bandha discovered a use-after-free in IndexedDB. If a user were
tricked in to opening a specially crafted message with scripting enabled,
an attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2015-0831)

Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij, Liz Henry, Byron
Campen, Tom Schuster, and Ryan VanderMeulen discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-0836)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703610");
  script_cve_id("CVE-2016-4463");
  script_tag(name:"creation_date", value:"2016-06-28 22:00:00 +0000 (Tue, 28 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 11:29:00 +0000 (Wed, 07 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-3610)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3610");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3610");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xerces-c' package(s) announced via the DSA-3610 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brandon Perry discovered that xerces-c, a validating XML parser library for C++, fails to successfully parse a DTD that is deeply nested, causing a stack overflow. A remote unauthenticated attacker can take advantage of this flaw to cause a denial of service against applications using the xerces-c library.

Additionally this update includes an enhancement to enable applications to fully disable DTD processing through the use of an environment variable (XERCES_DISABLE_DTD).

For the stable distribution (jessie), this problem has been fixed in version 3.1.1-5.1+deb8u3.

We recommend that you upgrade your xerces-c packages.");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
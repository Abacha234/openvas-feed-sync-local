# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703056");
  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_tag(name:"creation_date", value:"2014-10-25 22:00:00 +0000 (Sat, 25 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3056");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3056");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtasn1-3' package(s) announced via the DSA-3056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libtasn1-3, a library that manages ASN1 (Abstract Syntax Notation One) structures. An attacker could use those to cause a denial-of-service via out-of-bounds access or NULL pointer dereference.

For the stable distribution (wheezy), these problems have been fixed in version 2.13-2+deb7u1.

We recommend that you upgrade your libtasn1-3 packages.");

  script_tag(name:"affected", value:"'libtasn1-3' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
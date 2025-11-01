# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703082");
  script_cve_id("CVE-2014-8962", "CVE-2014-9028");
  script_tag(name:"creation_date", value:"2014-11-29 23:00:00 +0000 (Sat, 29 Nov 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3082)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3082");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3082");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flac' package(s) announced via the DSA-3082 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michele Spagnuolo, of Google Security Team, and Miroslav Lichvar, of Red Hat, discovered two issues in flac, a library handling Free Lossless Audio Codec media: by providing a specially crafted FLAC file, an attacker could execute arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 1.2.1-6+deb7u1.

For the testing distribution (jessie) and unstable distribution (sid), these problems have been fixed in version 1.3.0-3.

We recommend that you upgrade your flac packages.");

  script_tag(name:"affected", value:"'flac' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
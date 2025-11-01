# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703195");
  script_cve_id("CVE-2014-9705", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-1352", "CVE-2015-2305");
  script_tag(name:"creation_date", value:"2015-03-17 23:00:00 +0000 (Tue, 17 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3195");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3195");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the PHP language:

CVE-2015-2305

Guido Vranken discovered a heap overflow in the ereg extension (only applicable to 32 bit systems).

CVE-2014-9705

Buffer overflow in the enchant extension.

CVE-2015-0231

Stefan Esser discovered a use-after-free in the unserialisation of objects.

CVE-2015-0232

Alex Eubanks discovered incorrect memory management in the exif extension.

CVE-2015-0273

Use-after-free in the unserialisation of DateTimeZone.

For the stable distribution (wheezy), these problems have been fixed in version 5.4.38-0+deb7u1.

For the upcoming stable distribution (jessie), these problems have been fixed in version 5.6.6+dfsg-2.

For the unstable distribution (sid), these problems have been fixed in version 5.6.6+dfsg-2.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702406");
  script_cve_id("CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2406)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2406");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2406");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2406 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Icedove, Debian's variant of the Mozilla Thunderbird code base.

CVE-2011-3670

Icedove does not not properly enforce the IPv6 literal address syntax, which allows remote attackers to obtain sensitive information by making XMLHttpRequest calls through a proxy and reading the error messages.

CVE-2012-0442

Memory corruption bugs could cause Icedove to crash or possibly execute arbitrary code.

CVE-2012-0444

Icedove does not properly initialize nsChildView data structures, which allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via a crafted Ogg Vorbis file.

CVE-2012-0449

Icedove allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly execute arbitrary code via a malformed XSLT stylesheet that is embedded in a document.

For the stable distribution (squeeze), this problem has been fixed in version 3.0.11-1+squeeze7.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702534");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2534)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2534");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2534");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.4' package(s) announced via the DSA-2534 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities related to XML processing were discovered in PostgreSQL, an SQL database.

CVE-2012-3488

contrib/xml2's xslt_process() can be used to read and write external files and URLs.

CVE-2012-3489

xml_parse() fetches external files or URLs to resolve DTD and entity references in XML values.

This update removes the problematic functionality, potentially breaking applications which use it in a legitimate way.

Due to the nature of these vulnerabilities, it is possible that attackers who have only indirect access to the database can supply crafted XML data which exploits this vulnerability.

For the stable distribution (squeeze), these problems have been fixed in version 8.4.13-0squeeze1.

For the unstable distribution (sid), these problems have been fixed in version 9.1.5-1 of the postgresql-9.1 package.

We recommend that you upgrade your postgresql-8.4 packages.");

  script_tag(name:"affected", value:"'postgresql-8.4' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
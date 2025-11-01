# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71146");
  script_cve_id("CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868");
  script_tag(name:"creation_date", value:"2012-03-12 15:32:17 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2418");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.4' package(s) announced via the DSA-2418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in PostgreSQL, an object-relational SQL database. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-0866

It was discovered that the permissions of a function called by a trigger are not checked. This could result in privilege escalation.

CVE-2012-0867

It was discovered that only the first 32 characters of a host name are checked when validating host names through SSL certificates. This could result in spoofing the connection in limited circumstances.

CVE-2012-0868

It was discovered that pg_dump did not sanitise object names. This could result in arbitrary SQL command execution if a malformed dump file is opened.

For the stable distribution (squeeze), this problem has been fixed in version 8.4.11-0squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 8.4.11-1.

We recommend that you upgrade your postgresql-8.4 packages.");

  script_tag(name:"affected", value:"'postgresql-8.4' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
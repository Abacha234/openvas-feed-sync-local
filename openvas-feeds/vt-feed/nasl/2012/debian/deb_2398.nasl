# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71249");
  script_cve_id("CVE-2011-3389", "CVE-2012-0036");
  script_tag(name:"creation_date", value:"2012-04-30 11:55:40 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2398)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2398");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2398");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-2398 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in cURL, an URL transfer library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-3389

This update enables OpenSSL workarounds against the BEAST attack. Additional information can be found in the cURL advisory

CVE-2012-0036

Dan Fandrich discovered that cURL performs insufficient sanitising when extracting the file path part of an URL.

For the oldstable distribution (lenny), this problem has been fixed in version 7.18.2-8lenny6.

For the stable distribution (squeeze), this problem has been fixed in version 7.21.0-2.1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 7.24.0-1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
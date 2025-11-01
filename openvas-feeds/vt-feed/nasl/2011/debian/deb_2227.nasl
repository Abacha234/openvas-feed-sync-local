# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69570");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2227");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2227");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-2227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Iceape internet suite, an unbranded version of Seamonkey:

CVE-2011-0069 CVE-2011-0070 CVE-2011-0072 CVE-2011-0074 CVE-2011-0075 CVE-2011-0077 CVE-2011-0078 CVE-2011-0080 CVE-2011-0081 Scoobidiver, Ian Beer Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren, Jesse Ruderman, Aki Kelin and Martin Barbella discovered memory corruption bugs, which may lead to the execution of arbitrary code.

CVE-2011-0065 CVE-2011-0066 CVE-2011-0073 regenrecht discovered several dangling pointer vulnerabilities, which may lead to the execution of arbitrary code.

CVE-2011-0067

Paul Stone discovered that Java applets could steal information from the autocompletion history.

CVE-2011-0071

Soroush Dalili discovered a directory traversal vulnerability in handling resource URIs.

The oldstable distribution (lenny) is not affected. The iceape package only provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in version 2.0.11-5.

For the unstable distribution (sid), this problem has been fixed in version 2.0.14-1.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
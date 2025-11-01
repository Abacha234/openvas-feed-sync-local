# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66454");
  script_cve_id("CVE-2009-1829", "CVE-2009-2560", "CVE-2009-2562", "CVE-2009-3241", "CVE-2009-3550", "CVE-2009-3829");
  script_tag(name:"creation_date", value:"2009-12-09 23:23:54 +0000 (Wed, 09 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1942)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1942");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1942");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-1942 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Wireshark network traffic analyzer, which may lead to the execution of arbitrary code or denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-2560

A NULL pointer dereference was found in the RADIUS dissector.

CVE-2009-3550

A NULL pointer dereference was found in the DCERP/NT dissector.

CVE-2009-3829

An integer overflow was discovered in the ERF parser.

This update also includes fixes for three minor issues (CVE-2008-1829, CVE-2009-2562, CVE-2009-3241), which were scheduled for the next stable point update. Also CVE-2009-1268 was fixed for Etch. Since this security update was issued prior to the release of the point update, the fixes were included.

For the old stable distribution (etch), this problem has been fixed in version 0.99.4-5.etch.4.

For the stable distribution (lenny), this problem has been fixed in version 1.0.2-3+lenny7.

For the unstable distribution (sid) these problems have been fixed in version 1.2.3-1.

We recommend that you upgrade your Wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702792");
  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6340");
  script_tag(name:"creation_date", value:"2013-11-03 23:00:00 +0000 (Sun, 03 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2792)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2792");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2792");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-2792 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors for IEEE 802.15.4, NBAP, SIP and TCP, which could result in denial of service.

The oldstable distribution (squeeze) is only affected by CVE-2013-6340. This problem has been fixed in version 1.2.11-6+squeeze13.

For the stable distribution (wheezy), these problems have been fixed in version 1.8.2-5wheezy7.

For the unstable distribution (sid), these problems have been fixed in version 1.10.3-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702700");
  script_cve_id("CVE-2013-3555", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3562");
  script_tag(name:"creation_date", value:"2013-06-01 22:00:00 +0000 (Sat, 01 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2700)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2700");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2700");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-2700 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors for GTPv2, ASN.1 BER, PPP CCP, DCP ETSI, MPEG DSM-CC and Websocket, which could result in denial of service or the execution of arbitrary code.

The oldstable distribution (squeeze) is not affected.

For the stable distribution (wheezy), these problems have been fixed in version 1.8.2-5wheezy3.

For the unstable distribution (sid), these problems have been fixed in version 1.8.7-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
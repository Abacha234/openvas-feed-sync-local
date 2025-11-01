# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703367");
  script_cve_id("CVE-2015-6241", "CVE-2015-6242", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6247", "CVE-2015-6248", "CVE-2015-6249");
  script_tag(name:"creation_date", value:"2015-09-23 22:00:00 +0000 (Wed, 23 Sep 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3367");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3367");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors/parsers for ZigBee, GSM RLC/MAC, WaveAgent, ptvcursor, OpenFlow, WCCP and in internal functions which could result in denial of service.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 1.12.7+g7fc8978-1.

For the unstable distribution (sid), these problems have been fixed in version 1.12.7+g7fc8978-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
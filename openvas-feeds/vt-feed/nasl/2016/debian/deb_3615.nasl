# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703615");
  script_cve_id("CVE-2016-5350", "CVE-2016-5351", "CVE-2016-5353", "CVE-2016-5354", "CVE-2016-5355", "CVE-2016-5356", "CVE-2016-5357", "CVE-2016-5359");
  script_tag(name:"creation_date", value:"2016-07-01 22:00:00 +0000 (Fri, 01 Jul 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:24:00 +0000 (Mon, 28 Nov 2016)");

  script_name("Debian: Security Advisory (DSA-3615)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3615");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3615");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-3615 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the dissectors/parsers for PKTC, IAX2, GSM CBCH and NCP, SPOOLS, IEEE 802.11, UMTS FP, USB, Toshiba, CoSine, NetScreen, WBXML which could result in denial of service or potentially the execution of arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u7.

For the testing distribution (stretch), these problems have been fixed in version 2.0.4+gdd7746e-1.

For the unstable distribution (sid), these problems have been fixed in version 2.0.4+gdd7746e-1.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
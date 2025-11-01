# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892849");
  script_cve_id("CVE-2021-22207", "CVE-2021-22235", "CVE-2021-39921", "CVE-2021-39922", "CVE-2021-39923", "CVE-2021-39924", "CVE-2021-39925", "CVE-2021-39928", "CVE-2021-39929");
  script_tag(name:"creation_date", value:"2021-12-27 02:00:22 +0000 (Mon, 27 Dec 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-24 14:31:00 +0000 (Wed, 24 Nov 2021)");

  script_name("Debian: Security Advisory (DLA-2849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2849");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2849");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-2849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were fixed in the network traffic analyzer Wireshark.

CVE-2021-22207

Excessive memory consumption in the MS-WSP dissector.

CVE-2021-22235

Crash in the DNP dissector.

CVE-2021-39921

NULL pointer exception in the Modbus dissector.

CVE-2021-39922

Buffer overflow in the C12.22 dissector.

CVE-2021-39923

Large loop in the PNRP dissector.

CVE-2021-39924

Large loop in the Bluetooth DHT dissector.

CVE-2021-39925

Buffer overflow in the Bluetooth SDP dissector.

CVE-2021-39928

NULL pointer exception in the IEEE 802.11 dissector.

CVE-2021-39929

Uncontrolled Recursion in the Bluetooth DHT dissector.

For Debian 9 stretch, these problems have been fixed in version 2.6.20-0+deb9u2.

We recommend that you upgrade your wireshark packages.

For the detailed security status of wireshark please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
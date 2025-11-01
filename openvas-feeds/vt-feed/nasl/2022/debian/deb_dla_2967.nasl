# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892967");
  script_cve_id("CVE-2021-22191", "CVE-2021-4181", "CVE-2021-4184", "CVE-2021-4185", "CVE-2022-0581", "CVE-2022-0582", "CVE-2022-0583", "CVE-2022-0585", "CVE-2022-0586");
  script_tag(name:"creation_date", value:"2022-04-01 01:00:14 +0000 (Fri, 01 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 18:07:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Debian: Security Advisory (DLA-2967)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2967");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2967");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wireshark");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DLA-2967 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Wireshark, a network traffic analyzer. An attacker could cause a denial of service (infinite loop or application crash) via packet injection or a crafted capture file. Improper URL handling in Wireshark could also allow remote code execution. A double-click will no longer automatically open the URL in pcap(ng) files and instead copy it to the clipboard where it can be inspected and pasted to the browser's address bar.

For Debian 9 stretch, these problems have been fixed in version 2.6.20-0+deb9u3.

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